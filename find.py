#!/usr/bin/env python3

import sys
import binaryninja
import logging
import traceback
logging.basicConfig(level=logging.DEBUG)

import queue as Queue

def get_callstack(function, nb_iter=0):

    callers = function.callers

    if len(callers) == 0:
        return ""

    if nb_iter > 10:
        return ""

    paths = []

    for caller in callers:

        if caller == function:
            continue
        tmp_path = str(caller) + " -> " + str(function)
        all_paths = get_callstack(caller, nb_iter+1)

        if len(all_paths) == 0:
            paths += [tmp_path]
        for path in all_paths:
            paths += [path + " -> " + str(function)]

    return paths


def backward_slice(xref, op, param_number):

    ml = xref.function.mlil
    instr = ml[ml.get_instruction_start(op.address)].ssa_form

    var_s = instr.vars_read
    q = Queue.Queue()
    q.put(var_s[param_number])

    visited = []

    while not q.empty():

        var = q.get()
        visited += [var]
        if type(var) == binaryninja.mediumlevelil.SSAVariable:
            temp = [ml.get_ssa_var_definition(var)]
        else:
            temp = ml.get_var_definitions(var)

        for t in temp:
            if t is not None:

                print(f"Var {t.dest} reads from {t.src}")

                if t.src.operation == binaryninja.MediumLevelILOperation.MLIL_LOAD and hasattr(t.src.src, "constant"):
                    param_ptr = t.src.src.constant
                    read_string_argument(param_ptr)
                    assert(len(t.ssa_form.src.vars_read) == 0)
                    return True

                data = t.ssa_form.vars_read

                for j in data:

                    if j not in visited:
                        q.put(j)
    return False



def explore_children(op):

    operands = Queue.Queue()
    operands.put(*op.operands)
    # the call is apparently located in a child operation
    while not operands.empty():

        o = operands.get()
        operands.put(*o.operands)
        if hasattr(o, "operation") and o.operation == binaryninja.HighLevelILOperation.HLIL_CALL:
            op = o
            break
    else:
        raise Exception("Cannot find the function call O.o")
    return op


def is_relevant_bb(basic_block, function_name):

    for line in basic_block.disassembly_text:
        if function_name in str(line):
            logging.debug(str(line))
            return True

    return False


def is_relevant_line(instruction, function_name):

    for line in instruction.lines:
        if function_name.replace("sub_", "") in str(line):
            return True

    return False


def read_string_argument(param_ptr):

    string_value = bv.get_string_at(param_ptr)

    if string_value is not None:
        logging.info(
            f"LoadLibrary param is {string_value.value.encode('utf-8', errors='ignore')}")

    elif param_ptr != 0:

        a = bv.get_strings(param_ptr)
        weird_string = bv.read(param_ptr, 1).decode('utf-8') + a[0].value
        logging.info(f"LoadLibrary param is {weird_string}")

    else:
        raise Exception(f"Exception: String value is None @ {hex(param_ptr)}")

    return True


def find_param_to_fn_call_xref(xref, param_number=0, recursion_level=0, function_name="LoadLibrary"):

    logging.debug(f"Analyzing {xref.function}, call stack depth={recursion_level}")
    blocks = list(xref.function.high_level_il)
    found_instruction = False

    for basic_block in blocks:

        if not is_relevant_bb(basic_block, function_name):
            continue

        for x in basic_block:

            if found_instruction:
                break

            if not is_relevant_line(x, function_name):
                continue

            try:
                for op in x.operands:

                    if found_instruction:
                        break
                        
                    # handle function call in "if" statements or other similar cases
                    if not hasattr(op, "operation") or op.operation != binaryninja.HighLevelILOperation.HLIL_CALL:

                        if not hasattr(op, "lines") or not function_name.replace("sub_", "") in str(op.lines[0]):
                            continue

                        # function call is located further down the AST
                        op = explore_children(op)
                        found_instruction = True

                    # The function argument is a variable
                    if len(op.params) > param_number and not hasattr(op.params[param_number], "constant"):

                        # The variable is set by another function, climb up the call stack
                        if hasattr(op.params[0], "var") and "arg" in op.params[param_number].var.name:
                            nb_param = int(op.params[param_number].var.name.split("arg")[1]) - 1
                            logging.debug(f"Look for param number {nb_param} in any caller function.")

                            for xrf in bv.get_callers(xref.function.start):
                                logging.debug(f"That function is called at @ {hex(xrf.address)}")
                                found_instruction |= find_param_to_fn_call_xref(xrf, nb_param, recursion_level+1, xref.function.name)

                            if found_instruction:
                                break

                        found_instruction |= backward_slice(xref, op, param_number)

                    # The function argument is a constant string
                    elif hasattr(op.params[param_number], "constant"):
                        param_ptr = op.params[param_number].constant

                        found_instruction |= read_string_argument(param_ptr)

            except Exception as e:
                traceback.print_exc()
                logging.error("Exception: " + str(e))

        if found_instruction:
            break

    return found_instruction


if __name__ == "__main__":

    if len(sys.argv) < 2:
        logging.error("Usage: find.py /path/to/bin")

    target = sys.argv[1]
    bv = binaryninja.BinaryViewType.get_view_of_file(target, update_analysis=True)

    #a = bv.get_symbols_by_name("LoadLibraryA")
    a = bv.get_symbols()

    addresses = []
    success = 0
    errors = 0
    for symbol in a:

        if symbol.type == binaryninja.SymbolType.ImportAddressSymbol:

            if "LoadLibrary" in symbol.name:

                logging.info(f"Found {symbol.name} @ {hex(symbol.address)}")
                addresses += [symbol.address]

    for addr in addresses:

        xrefs = bv.get_code_refs(addr)

        logging.debug(xrefs)
        for xref in xrefs:
            res = find_param_to_fn_call_xref(xref)

            if res:
                cs = get_callstack(xref.function)
                if len(cs) == 0:
                    errors += 1
                    continue
                success += 1
                logging.info("Success. Here is the callstack:")
                logging.info(cs)
            else:
                errors += 1

    logging.info(f"Done. {success} successes, {errors} errors.")
