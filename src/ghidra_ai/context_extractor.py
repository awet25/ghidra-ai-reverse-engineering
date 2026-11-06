from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.data import StringDataInstance, TypeDef, Undefined, VoidDataType
from ghidra.program.model.pcode import HighGlobal, HighLocal, HighParam, PcodeOp
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor
from .models import (
    CalleeContext, CalleePreview, CallSiteContext, FunctionContext, SupportingFunctionContext,
)



class ContextExtractor:
    PREVIEW_MAX_STRINGS = 12
    PREVIEW_MAX_STRING_LENGTH = 160
    MAX_SUPPORTING_FUNCTIONS = 5
    MAX_SUPPORTING_CODE_CHARS = 16000

    def __init__(self, program):
        self.program = program

        self.decompiler = DecompInterface()
        self._decompiler_error = None
        self.decompiler.setOptions(DecompileOptions())
        self.decompiler.toggleCCode(True)
        self.decompiler.toggleSyntaxTree(True)
        self.decompiler.setSimplificationStyle("decompile")

        if not self.decompiler.openProgram(program):
            self._decompiler_error = "Could not open program in decompiler."

    def _decompile_function(self, function, monitor):
        if self._decompiler_error is not None:
            raise RuntimeError(self._decompiler_error)
        result = self.decompiler.decompileFunction(
            function,
            30,
            monitor
        )

        if not result.decompileCompleted():
            raise RuntimeError(
                result.getErrorMessage()
            )

        return result


    def get_called_functions(self, function, monitor):
        """Return distinct call targets, resolving Ghidra-recognized thunks."""
        return list(self._get_called_function_map(function, monitor).values())

    def get_callee_contexts(self, function, monitor):
        """Discover root call relationships and attach non-recursive body previews.

        Count each instruction once per destination, even if it has duplicate
        references. Computed/indirect calls are included only when Ghidra has a
        call reference to an exact Function entry point. Unresolved calls,
        data references (including unresolved pointer slots), and jumps are
        skipped rather than guessing a function or following data pointers.
        Each distinct internal target receives one Listing-only preview; its
        outgoing targets are counted, but their bodies are never inspected.
        """
        manager = self.program.getFunctionManager()
        instructions = self.program.getListing().getInstructions(
            function.getBody(), True
        )
        callees = {}
        previews = {}  # Per root extraction; aliases share one target-body scan.
        while instructions.hasNext():
            if monitor is not None:
                monitor.checkCancelled()
            instruction = instructions.next()
            seen_targets = set()
            for reference in instruction.getReferencesFrom():
                if not reference.getReferenceType().isCall():
                    continue
                callee = manager.getFunctionAt(reference.getToAddress())
                if callee is None:
                    continue
                address = str(callee.getEntryPoint())
                if address in seen_targets:
                    continue
                seen_targets.add(address)
                if address not in callees:
                    context = CalleeContext(
                        name=str(callee.getName()),
                        address=address,
                        is_external=bool(callee.isExternal()),
                        is_thunk=bool(callee.isThunk()),
                    )
                    target = callee
                    if context.is_thunk:
                        # Resolve aliases only; no recursive call-graph traversal.
                        target = callee.getThunkedFunction(True)
                        if target is not None:
                            context.thunk_target_name = str(target.getName())
                            context.thunk_target_address = str(target.getEntryPoint())
                            context.thunk_target_is_external = bool(target.isExternal())
                    self._attach_preview(
                        context, target if target is not None else callee, previews, monitor
                    )
                    callees[address] = context
                callees[address].call_count += 1
        return list(callees.values())

    def _attach_preview(self, context, target, cache, monitor):
        if target.isExternal():
            return
        address = str(target.getEntryPoint())
        if address not in cache:
            try:
                cache[address] = (self._get_callee_preview(target, monitor), None)
            except Exception as error:
                if monitor is not None:
                    monitor.checkCancelled()
                cache[address] = (None, str(error))
        context.preview, context.preview_error = cache[address]

    def _get_callee_preview(self, function, monitor):
        """Scan this body only; outgoing targets supply identity/flags, never bodies."""
        listing = self.program.getListing()
        manager = self.program.getFunctionManager()
        body = function.getBody()
        preview = CalleePreview(
            name=str(function.getName()), address=str(function.getEntryPoint()),
            body_size=int(body.getNumAddresses()),
            is_external=bool(function.isExternal()), is_thunk=bool(function.isThunk()),
        )
        if preview.is_thunk:
            target = function.getThunkedFunction(True)
            if target is not None:
                preview.thunk_target_address = str(target.getEntryPoint())
        self._add_preview_signature(preview, function, monitor)
        try:
            blocks = BasicBlockModel(self.program).getCodeBlocksContaining(
                body, monitor if monitor is not None else TaskMonitor.DUMMY
            )
            count = 0
            while blocks.hasNext():
                if monitor is not None:
                    monitor.checkCancelled()
                blocks.next()
                count += 1
            preview.basic_block_count = count
        except Exception as error:
            if monitor is not None:
                monitor.checkCancelled()
            preview.errors.append(f"Basic blocks unavailable: {error}")
        counts = {"CALL": 0, "CALLIND": 0, "LOAD": 0, "STORE": 0}
        opcodes = {getattr(PcodeOp, name): name for name in counts}
        internal, external, strings = set(), set(), set()
        pcode_error = False
        raw_operation_count = 0
        string_error = False
        instructions = listing.getInstructions(body, True)
        while instructions.hasNext():
            if monitor is not None:
                monitor.checkCancelled()
            instruction = instructions.next()
            preview.instruction_count += 1
            try:
                # Include Ghidra flow overrides. This does not invoke the decompiler.
                for op in instruction.getPcode(True):
                    raw_operation_count += 1
                    name = opcodes.get(op.getOpcode())
                    if name is not None:
                        counts[name] += 1
            except Exception as error:
                if monitor is not None:
                    monitor.checkCancelled()
                if not pcode_error:
                    preview.errors.append(f"Raw P-code unavailable: {error}")
                pcode_error = True
            direct_call = False
            for reference in instruction.getReferencesFrom():
                if reference.getReferenceType().isCall():
                    target = manager.getFunctionAt(reference.getToAddress())
                    if target is not None:
                        direct_call |= not reference.getReferenceType().isComputed()
                        resolved = target.getThunkedFunction(True) if target.isThunk() else None
                        target = resolved if resolved is not None else target
                        targets = external if target.isExternal() else internal
                        targets.add(str(target.getEntryPoint()))
                try:
                    value = self._get_reference_string(reference, listing)
                except Exception as error:
                    if monitor is not None:
                        monitor.checkCancelled()
                    if not string_error:
                        preview.errors.append(f"Referenced strings incomplete: {error}")
                    string_error = True
                    continue
                if value:
                    preview.strings_truncated |= len(value) > self.PREVIEW_MAX_STRING_LENGTH
                    strings.add(value[:self.PREVIEW_MAX_STRING_LENGTH])
                    if len(strings) > self.PREVIEW_MAX_STRINGS:
                        strings.remove(max(strings))
                        preview.strings_truncated = True
            preview.direct_call_site_count += int(direct_call)
        preview.internal_callee_count = len(internal)
        preview.external_callee_count = len(external)
        preview.strings = sorted(strings)
        if preview.instruction_count and not raw_operation_count and not pcode_error:
            preview.errors.append("Raw P-code unavailable: no operations returned")
            pcode_error = True
        preview.pcode_counts = None if pcode_error else counts
        return preview

    @staticmethod
    def _add_preview_signature(preview, function, monitor):
        try:
            source = function.getSignatureSource()
            preview.signature_source = str(source)
            # Default/analysis-only signatures may have unrecovered parameters
            # and returns. Names (including FUN_*) never affect this decision.
            if source in (SourceType.IMPORTED, SourceType.USER_DEFINED):
                preview.parameter_count = int(function.getParameterCount())
                datatype = function.getReturnType()
                if isinstance(datatype, TypeDef):
                    datatype = datatype.getBaseDataType()
                if isinstance(datatype, VoidDataType):
                    preview.has_return_value = False
                elif not Undefined.isUndefined(datatype):
                    preview.has_return_value = True
        except Exception as error:
            if monitor is not None:
                monitor.checkCancelled()
            preview.errors.append(f"Signature metadata unavailable: {error}")

    @staticmethod
    def _get_reference_string(reference, listing):
        if not reference.getReferenceType().isData():
            return None
        address = reference.getToAddress()
        data = listing.getDataAt(address)
        if data is None:
            data = listing.getDataContaining(address)
        if data is None or not StringDataInstance.isString(data):
            return None
        value = StringDataInstance.getStringDataInstance(data).getStringValue()
        return str(value) if value else None

    def _get_called_function_map(self, function, monitor):
        called_functions = function.getCalledFunctions(
            monitor
        )
        callees = {}
        for callee in called_functions:
            target = callee.getThunkedFunction(True) if callee.isThunk() else None
            if target is None:
                target = callee
            callees[str(target.getEntryPoint())] = str(target.getName())
        return callees

    def _augment_call_sites(self, context, high_function, monitor):
        """Inspect only this HighFunction; never decompile or expand its callees."""
        callees = {callee.address: callee for callee in context.callee_contexts}
        operations = high_function.getPcodeOps()
        while operations.hasNext():
            if monitor is not None:
                monitor.checkCancelled()
            op = operations.next()
            # Decoded PcodeOpAST.isDead() is unreliable in Ghidra 12.1.3;
            # attached operations have a parent basic block, detached ones do not.
            if op.getParent() is None or op.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
                continue
            try:
                site = self._describe_call_site(op)
                if op.getOpcode() == PcodeOp.CALLIND:
                    # A remaining CALLIND has no concrete High P-code target.
                    # Reference candidates alone are not proof of its destination.
                    context.indirect_call_sites.append(site)
                    continue
                target = self.program.getFunctionManager().getFunctionAt(
                    op.getInput(0).getAddress()
                )
                if target is not None:
                    site.target_address = str(target.getEntryPoint())
                    site.target_status = "resolved_unmatched"
                    callee = self._match_pcode_callee(op, site.target_address, callees)
                    if callee is not None:
                        site.target_status = "resolved"
                        callee.call_sites.append(site)
                        continue
                context.unmatched_call_sites.append(site)
            except Exception as error:
                if monitor is not None:
                    monitor.checkCancelled()
                context.extraction_errors.append(f"High P-code call skipped: {error}")

    def _match_pcode_callee(self, op, target_address, callees):
        # The decompiler may replace a thunk address with its final target.
        # Prefer same-instruction references, never merge aliases by name.
        address = op.getSeqnum().getTarget()
        instruction = (
            self.program.getListing().getInstructionAt(address)
            if address is not None else None
        )
        referenced = set()
        if instruction is not None:
            for ref in instruction.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    address = str(ref.getToAddress())
                    if address in callees:
                        referenced.add(address)
        matches = [callees[address] for address in referenced if target_address in (
            address, callees[address].thunk_target_address
        )]
        if len(matches) == 1:
            return matches[0]
        if not referenced:
            return callees.get(target_address)
        return None  # Conflicting or ambiguous same-site references stay unmatched.

    def _describe_call_site(self, op):
        sequence = op.getSeqnum()
        address = sequence.getTarget()
        output = op.getOutput()
        consumers = (
            [consumer for consumer in output.getDescendants() if consumer.getParent() is not None]
            if output is not None else []
        )
        return CallSiteContext(
            address=str(address) if address is not None else None,
            pcode_time=int(sequence.getTime()),
            call_kind="CALL" if op.getOpcode() == PcodeOp.CALL else "CALLIND",
            argument_count=max(0, op.getNumInputs() - 1),
            argument_provenance=[
                self._argument_provenance(op.getInput(index))
                for index in range(1, op.getNumInputs())
            ],
            has_output=output is not None,
            return_consumed=bool(consumers),
            return_uses=self._return_uses(output, consumers),
        )

    @staticmethod
    def _argument_provenance(varnode):
        if varnode.isConstant():
            return "constant"  # A numeric constant is not assumed to be a pointer.
        high = varnode.getHigh()
        if isinstance(high, HighParam):
            return "parameter"
        if isinstance(high, HighGlobal):
            return "global/address"
        if isinstance(high, HighLocal):
            return "local/temporary"
        return "unknown"

    @staticmethod
    def _return_uses(output, consumers):
        if output is None:
            return ["no_output"]
        if not consumers:
            return ["unused_output"]
        uses = set()
        for consumer in consumers:
            opcode = consumer.getOpcode()
            if opcode in (PcodeOp.CBRANCH, PcodeOp.BRANCHIND):
                uses.add("conditional/control_flow")
            elif opcode == PcodeOp.STORE and consumer.getInput(2) == output:
                uses.add("stored_to_memory")
            elif opcode in (PcodeOp.CALL, PcodeOp.CALLIND):
                if any(
                    consumer.getInput(i) == output
                    for i in range(1, consumer.getNumInputs())
                ):
                    uses.add("passed_to_call")
                if consumer.getInput(0) == output:
                    uses.add("conditional/control_flow")
            elif str(consumer.getMnemonic()).startswith(("INT_", "FLOAT_", "BOOL_")) or opcode in (
                PcodeOp.PTRADD, PcodeOp.PTRSUB, PcodeOp.PIECE, PcodeOp.SUBPIECE,
            ):
                uses.add("computation")
                # One bounded hop catches common compare-then-branch patterns.
                # No recursive slicing through copies, phi nodes, or arithmetic.
                result = consumer.getOutput()
                if result is not None and any(
                    descendant.getParent() is not None and descendant.getOpcode() == PcodeOp.CBRANCH
                    for descendant in result.getDescendants()
                ):
                    uses.add("conditional/control_flow")
            else:
                uses.add("other/unknown")
        return sorted(uses)

    def get_calling_functions(self, function, monitor):
        """Include callers of recognized thunks that lead to this function."""
        calling_functions = list(function.getCallingFunctions(monitor))
        thunk_addresses = function.getFunctionThunkAddresses(True)
        if thunk_addresses is not None:
            manager = self.program.getFunctionManager()
            for address in thunk_addresses:
                thunk = manager.getFunctionAt(address)
                if thunk is not None:
                    calling_functions.extend(thunk.getCallingFunctions(monitor))
        callers = {
            str(caller.getEntryPoint()): str(caller.getName())
            for caller in calling_functions
        }
        return list(callers.values())

    def get_strings(self, function):
        listing = self.program.getListing()
        strings = set()
        instructions = listing.getInstructions(function.getBody(), True)
        while instructions.hasNext():
            instruction = instructions.next()
            for operand_index in range(instruction.getNumOperands()):
                for reference in instruction.getOperandReferences(operand_index):
                    value = self._get_reference_string(reference, listing)
                    if value:
                        strings.add(value)
        return sorted(strings)

    def _add_supporting_functions(self, context, selections, monitor):
        if selections is None:
            return
        # Only identities already established from root call references qualify.
        allowed, relationships = {}, {}
        for callee in context.callee_contexts:
            if callee.is_external or callee.thunk_target_is_external:
                continue
            implementation = callee.thunk_target_address or callee.address
            allowed[callee.address] = implementation
            allowed[implementation] = implementation
            relationships.setdefault(implementation, []).append(callee.address)
        manager = self.program.getFunctionManager()
        seen = set()
        for selection in selections:
            if monitor is not None:
                monitor.checkCancelled()
            label = str(selection)
            try:
                if hasattr(selection, "getEntryPoint"):
                    address = selection.getEntryPoint()
                    label = str(address)
                    if hasattr(selection, "getProgram") and selection.getProgram() != self.program:
                        raise ValueError("function belongs to another program")
                elif isinstance(selection, str):
                    address = self.program.getAddressFactory().getAddress(selection)
                else:
                    address = selection  # Ghidra Address objects are accepted directly.
                if address is None:
                    raise ValueError("invalid entry address")
                function = manager.getFunctionAt(address)
                if function is None:
                    raise ValueError("no Function at exact entry address")
                requested = str(function.getEntryPoint())
                label = f"{function.getName()} @ {requested}"
                if requested == context.address:
                    raise ValueError("root cannot be selected as supporting context")
                if function.isExternal():
                    raise ValueError("external functions cannot be supporting context")
                target = function.getThunkedFunction(True) if function.isThunk() else function
                if target is None:
                    raise ValueError("thunk implementation is unresolved")
                implementation = str(target.getEntryPoint())
                if implementation == context.address:
                    raise ValueError("resolved implementation is the root")
                if target.isExternal():
                    raise ValueError("resolved implementation is external")
                if allowed.get(requested) != implementation:
                    raise ValueError("not a direct resolved internal callee of the root")
                if implementation in seen:
                    raise ValueError("duplicate supporting implementation ignored")
                if len(context.supporting_functions) >= self.MAX_SUPPORTING_FUNCTIONS:
                    raise ValueError(f"maximum {self.MAX_SUPPORTING_FUNCTIONS} supporting functions reached")
                seen.add(implementation)
                support = SupportingFunctionContext(
                    name=str(target.getName()), address=implementation,
                    parent_address=context.address, selected_address=requested,
                    called_addresses=list(relationships[implementation]),
                )
                context.supporting_functions.append(support)
                self._extract_supporting_function(support, target, monitor)
            except Exception as error:
                if monitor is not None:
                    monitor.checkCancelled()
                context.supporting_selection_errors.append(f"{label}: {error}")

    def _extract_supporting_function(self, support, function, monitor):
        # Do not call extract(), inspect High P-code, or construct nested contexts.
        try:
            result = self._decompile_function(function, monitor)
            code = str(result.getDecompiledFunction().getC())
            support.decompilation_succeeded = True
            support.decompiled_code = code[:self.MAX_SUPPORTING_CODE_CHARS]
            support.code_truncated = len(code) > self.MAX_SUPPORTING_CODE_CHARS
            if support.code_truncated:
                support.extraction_errors.append(
                    f"Decompiled code truncated to {self.MAX_SUPPORTING_CODE_CHARS} characters"
                )
        except Exception as error:
            if monitor is not None:
                monitor.checkCancelled()
            support.extraction_errors.append(f"Decompilation unavailable: {error}")
        try:
            strings = self.get_strings(function)  # This function's body only.
            support.strings = [
                value[:self.PREVIEW_MAX_STRING_LENGTH]
                for value in strings[:self.PREVIEW_MAX_STRINGS]
            ]
            support.strings_truncated = (
                len(strings) > self.PREVIEW_MAX_STRINGS
                or any(len(value) > self.PREVIEW_MAX_STRING_LENGTH for value in strings)
            )
            if support.strings_truncated:
                support.extraction_errors.append("Supporting strings truncated to preview limits")
        except Exception as error:
            if monitor is not None:
                monitor.checkCancelled()
            support.extraction_errors.append(f"Referenced strings unavailable: {error}")


    def extract(self, function, monitor, supporting_functions=None):
        """Extract one root, optionally with up to five explicitly selected direct callees.

        Selections may be Function objects, Ghidra Address objects, or entry-address
        strings. Input order determines budget order; nothing is selected implicitly.
        """
        callees = self.get_called_functions(
            function,
            monitor
        )

        callers = self.get_calling_functions(
            function,
            monitor
        )

        strings = self.get_strings(
            function
        )

        context = FunctionContext(
            name=str(function.getName()),
            address=str(
                function.getEntryPoint()
            ),
            decompiled_code="",
            callers=callers,
            callees=callees,
            strings=strings,
            callee_contexts=self.get_callee_contexts(function, monitor),
        )
        try:
            result = self._decompile_function(function, monitor)
        except Exception as error:
            if monitor is not None:
                monitor.checkCancelled()
            context.extraction_errors.append(f"Decompilation unavailable: {error}")
            self._add_supporting_functions(context, supporting_functions, monitor)
            return context
        try:
            context.decompiled_code = str(result.getDecompiledFunction().getC())
        except Exception as error:
            if monitor is not None:
                monitor.checkCancelled()
            context.extraction_errors.append(f"Decompiled C unavailable: {error}")
        try:
            high_function = result.getHighFunction()
            if high_function is None:
                context.extraction_errors.append("High P-code unavailable: no HighFunction")
            else:
                self._augment_call_sites(context, high_function, monitor)
        except Exception as error:
            if monitor is not None:
                monitor.checkCancelled()
            context.extraction_errors.append(f"High P-code unavailable: {error}")
        self._add_supporting_functions(context, supporting_functions, monitor)
        return context

    def close(self):
        self.decompiler.dispose()
