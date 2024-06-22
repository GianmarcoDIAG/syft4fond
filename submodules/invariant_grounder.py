#! /usr/bin/env python3

from itertools import product

if __name__ == "__main__":
    print("Grounding invariants...", end="")

    # 1. Open files of interest
    predicates_file = open("predicates_file.txt", "r")
    objects_file = open("objects_file.txt", "r")
    invariants_file = open("invariants_file.txt", "r")
    grounded_file = open("grounded_invs.txt", "w")

    # 2. Define predicates
    pred_to_types = dict()
    line = predicates_file.readline()
    while (line != ""):
        index = line.find("(")
        pred_name = line[0:index]
        pred_types_str = line[index+1:len(line)-2]
        pred_types_list = pred_types_str.split(" ")
        pred_types = []
        for i in range(1, len(pred_types_list), 2):
            pred_types.append(pred_types_list[i].strip(","))
        pred_to_types[pred_name] = pred_types
        line = predicates_file.readline()

    # for pred in pred_to_types:
    #     print("Predicate name: " + pred + ". Predicate types: " + str(pred_to_types[pred]))

    predicates_file.close()

    # 3. Assign objects to types
    types_to_objs = dict()
    line = objects_file.readline()
    while (line != ""):
        line_list = line.split(" ")
        obj = line_list[0].strip(":")
        obj_type = line_list[1].strip("\n")
        if obj_type in types_to_objs:
            types_to_objs[obj_type].append(obj)
        else:
            types_to_objs[obj_type] = [obj]
        line = objects_file.readline()

    # for obj_type in types_to_objs:
        # print("Type: " + obj_type + ". Objects: ", end="")
        # for obj in types_to_objs[obj_type]:
            # print(obj + " ", end="")
        # print()
    
    objects_file.close()

    # 4. Ground invariants
    line = invariants_file.readline()
    while (line != ""):
        inv_string = ""
        line = line[1:len(line)-2]
        line_list = line.split("; ")
        # print("Invariant: ", line_list)
        for atom in line_list:
            atom = atom.strip("Atom")
            atom = atom.strip() # TODO. What happens with negative predicates?
            index = atom.find("(")
            pred_name = atom[0:index]
            atom_objs_str = atom[index+1:-1]
            atom_objs_list = atom_objs_str.split(", ")
            var_indexes = []
            for i in range(len(atom_objs_list)):
                if atom_objs_list[i].startswith("?"):
                    var_indexes.append(i)
            atom_types = pred_to_types[pred_name]
            product_args = []
            for i in range(0, len(atom_types)):
                if i in var_indexes:
                    type_objs = types_to_objs[(atom_types[i])]
                    product_args.append(type_objs)
                else:
                    product_args.append([atom_objs_list[i]])
            cartesian_product = product(*product_args)
            cartesian_product = list(cartesian_product)
            for i in range(0, len(cartesian_product)):
                if len(cartesian_product[i]) == 1:
                    inv_string +=  pred_name + str(cartesian_product[i]).replace(",", "").replace("'", "") + ";"
                else: 
                    inv_string +=  pred_name + str(cartesian_product[i]).replace("'", "") + ";"
        if inv_string.count(";") > 1: 
            grounded_file.write(inv_string.strip(";")+"\n")
        line = invariants_file.readline()

    invariants_file.close()
    grounded_file.close()

    print("Done!")