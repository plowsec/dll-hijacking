#!/usr/bin/env python3

import sys
import binaryninja
import logging

logging.basicConfig(level=logging.DEBUG)


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


def find_param_to_fn_call_xref(xref, param_number=0):

    print(f"Called by {xref.function}")
    blocks = list(xref.function.high_level_il)
    found_instruction = False
    for basic_block in blocks:

        for x in basic_block:
            if x.address < xref.address:
                continue

            if found_instruction:
                break

            try:
                for op in x.operands:
                    if not hasattr(op, "operation") or op.operation != binaryninja.HighLevelILOperation.HLIL_CALL:
                        continue

                    if not hasattr(op.params[param_number], "constant"):

                        if "arg" in op.params[0].var.name:
                            print("Yeah, trivial case identified")
                            nb_param = int(op.params[param_number].var.name.split("arg")[1])
                            print(f"Look for param number {nb_param} in any caller function.")
                            # TODO
                            c = xref.function.call_sites
                            for xrf in bv.get_callers(xref.function.start):
                                print(f"That function is called at @ {hex(xrf.address)}")
                                find_param_to_fn_call_xref(xrf, nb_param)
                        raise Exception("toto")

                    param_ptr = op.params[param_number].constant
                    string_value = bv.get_string_at(param_ptr)
                    if string_value is not None:
                        found_instruction = True
                        print(
                            f"LoadLibrary param is {string_value.value.encode('utf-8', errors='ignore')}")

                        break

                    else:
                        raise Exception("Exception: String value is None")

            except Exception as e:
                print(e)
                for line in x.il_basic_block.disassembly_text:
                    if "LoadLibrary" in str(line):
                        print(line)
                        # print(line.tokens[-1])
                        found_instruction = True
                        break

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
    for symbol in a:

        if symbol.type == binaryninja.SymbolType.ImportAddressSymbol:

            if "LoadLibrary" in symbol.name:

                logging.info(f"Found {symbol.name} @ {hex(symbol.address)}")
                addresses += [symbol.address]

    for addr in addresses:

        xrefs = bv.get_code_refs(addr)

        print(xrefs)
        for xref in xrefs:
            res = find_param_to_fn_call_xref(xref)

            if res:
                cs = get_callstack(xref.function)
                if len(cs) == 0:
                    continue
                print("Callstack:")
                print(cs)


    print("Done")
