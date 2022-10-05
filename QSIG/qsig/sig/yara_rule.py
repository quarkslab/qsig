"""
A library to create YARA rules.
-------------------------------

Copyright 2018 Mike Matonis

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
 without restriction, including without limitation the rights to use, copy, modify,
  merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to the following
  conditions:

The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-------------------------------

Adapted by dm to fit its needs.
"""

import collections
import io
import os
import re
from copy import deepcopy
from typing import Union, List, Optional, Dict, Generator

import yara

import qsig.exc

Multiple = Union[str, List[str]]
MaybeMultiple = Optional[Multiple]

YARA_KEYWORD = [
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "condition",
    "contains",
    "entrypoint",
    "false",
    "filesize",
    "fullword",
    "for",
    "global",
    "in",
    "import",
    "include",
    "int8",
    "int16",
    "int32",
    "int8be",
    "int16be",
    "int32be",
    "matches",
    "meta",
    "nocase",
    "not",
    "or",
    "of",
    "private",
    "rule",
    "strings",
    "them",
    "true",
    "uint8",
    "uint16",
    "uint32",
    "uint8be",
    "uint16be",
    "uint32be",
    "wide",
    "xor",
]

YARA_STR = re.compile(r"^[a-zA-Z]\w*?$")


def sanitize_string(input_: str) -> str:
    """
    Sanitize a string to avoid YARA keywords and replace forbidden characters.
    """
    if any(keyword == input_ for keyword in YARA_KEYWORD):
        raise ValueError("YARA keywords cannot be used as identifiers")

    new_input = input_.replace("-", "")
    if YARA_STR.match(new_input):
        # FIX : YARA only allows identifier up to 128 chars
        if len(new_input) >= 128:
            new_input = new_input[:127]
        return new_input

    raise ValueError


def generate_identifier() -> Generator[str, None, None]:
    for char in [
        "s",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "a",
        "t",
        "u",
        "v",
        "w",
        "x",
        "y",
        "z",
    ]:
        yield char

    raise ValueError


def raw_to_hex(raw_data: Union[bytes, str]) -> str:
    """Encode a raw string or bytes to hex representation"""
    if type(raw_data) is str:
        raw_data = raw_data.encode("utf-8")
    return bytes.hex(raw_data)


class Rule:
    """Rule class - representing a YARA rule"""

    def __init__(
        self,
        name: str,
        default_identifier: Union[str, bool] = False,
        tags: Optional[Union[str, List[str]]] = None,
        default_condition: Optional[str] = None,
        default_boolean: Optional[str] = None,
        identifier_template: Optional[str] = None,
        global_: bool = False,
        private: bool = False,
        default_str_condition: Optional[str] = None,
        meta: Optional[Dict[str, str]] = None,
    ):
        """."""
        self.name: str = sanitize_string(str(name))
        self.global_rule: bool = global_
        self.private_rule: bool = private

        self._strings: List = []
        self._conditions: List = []
        self.__proto_conditions = False  # ::list obj
        self.__proto_condition_groups = False  # :: dict obj
        self.__condition_groups = False  # ::dict obj

        self.identifier_template: str = "IDENTIFIER"
        if identifier_template is not None:
            self.identifier_template = identifier_template

        self.__authoritative_condition = False
        self.__string_struct = {
            "type": "",
            "identifier": "",
            "strings": "",
            "modifiers": "",
            "condition": "",
            "comment": "",
            "condition_group": "",
            "default_boolean": "",
        }

        self.used_identifiers: List[str] = [self.identifier_template]
        self.default_identifier: Union[str, bool] = default_identifier

        self.tags: List[str] = []
        if tags is not None:
            self.add_tags(tags)

        self.default_str_condition: str = "all of"
        if default_str_condition is not None:
            self.default_str_condition = default_str_condition

        self.default_condition: str = "all of them"
        if default_condition is not None:
            self.default_condition = default_condition

        self.legal_booleans = ["and", "or", "not"]
        if default_boolean is not None and default_boolean in self.legal_booleans:
            self.default_boolean = default_boolean
        else:
            self.default_boolean = "and"

        self._meta: Dict[str, str] = {}
        if meta is not None:
            self._meta.update(meta)

    def add_meta(self, key: str, value: str) -> None:
        """."""
        self._meta[key] = value

    def create_for_loop(self, expression, identifier, indexes, condition):
        """."""
        return f"""
        for {expression} {identifier} in ({indexes}):
        (
            {condition}
        )
        """

    def create_condition_group(
        self,
        name,
        default_boolean=False,
        parent_group=False,
        condition_modifier=False,
        virtual=False,
    ):
        """."""

        def proc_child(parent, child_name):

            if parent in dict(self.__condition_groups).keys():
                if self.__condition_groups[parent]["children"]:
                    self.__condition_groups[parent]["children"].append(child_name)
                else:
                    self.__condition_groups[parent]["children"] = [child_name]

        def init_condition_group(
            name,
            default_boolean,
            parent=False,
            condition_modifier=condition_modifier,
            virtual=False,
        ):

            group_struct = {
                "default_boolean": default_boolean,
                "conditions": list(),
                "parent": parent,
                "modifier": condition_modifier,
                "virtual": virtual,
                "children": False,
            }

            self.__condition_groups[name] = deepcopy(group_struct)

            if type(parent) == list:
                for p in parent:
                    proc_child(parent=p, child_name=name)
            else:
                proc_child(parent=parent, child_name=name)

        if default_boolean:
            if not default_boolean in self.legal_booleans:
                return False
        else:
            default_boolean = "and"

        if not self.__condition_groups:
            self.__condition_groups = collections.OrderedDict()

        if type(name) == list:
            for n in name:
                if not n in self.__condition_groups:
                    init_condition_group(
                        n, default_boolean, parent_group, condition_modifier, virtual
                    )
        else:
            if not name in self.__condition_groups:
                init_condition_group(
                    name, default_boolean, parent_group, condition_modifier, virtual
                )

    def get_condition_group(self, name):
        """."""

        #::This chunk creates a concept of 'prototyping' of the group

        self.__proto_conditions = []
        self.__proto_condition_groups = self.__condition_groups

        if name in self.__proto_condition_groups:
            self.process_conditions(condition_groups=True, prototype=True)

            tmp_conditions = self.proc_cond_str(self.__proto_condition_groups[name])

            self.__proto_conditions = []
            self.__proto_condition_groups = dict()

            return tmp_conditions

    def process_as_condition_group(self, condition, boolean):
        """."""

        if boolean in self.legal_booleans:
            if type(condition) == list:
                return "(%s)" % (" %s " % boolean).join(condition)
            elif type(condition) == str:
                return "(%s)" % condition
            else:
                return False
        else:
            return False

    def add_condition(
        self,
        condition,
        condition_group=False,
        default_boolean=False,
        parent_group=False,
        condition_modifier=False,
        prototype=False,
    ):
        """."""

        def add_condition_to_group(condition, group):

            self.create_condition_group(
                name=group,
                default_boolean=default_boolean,
                parent_group=parent_group,
                condition_modifier=condition_modifier,
            )

            if type(condition) == list:
                for c in condition:
                    if (
                        not c in global_condition_groups[group]["conditions"]
                    ):  # ::dev, unsure if we're breaking things
                        global_condition_groups[group]["conditions"].append(c)
            else:
                if condition:
                    if (
                        not condition in global_condition_groups[group]["conditions"]
                    ):  # ::dev, unsure if we're breaking things
                        global_condition_groups[group]["conditions"].append(condition)

        def add_global_condition(condition):
            if not condition in global_conditions:
                if isinstance(condition, Rule):
                    global_conditions.append(condition.name)
                else:
                    global_conditions.append(str(condition))

        if not condition:
            return False

        # Prototype support for get_condition_group
        global_condition_groups = None
        global_conditions = None

        if prototype:
            global_condition_groups = self.__proto_condition_groups
            global_conditions = self.__proto_conditions
        else:
            global_condition_groups = self.__condition_groups
            global_conditions = self._conditions

        if condition_group:
            if type(condition_group) == list:
                for cg in condition_group:
                    add_condition_to_group(condition=condition, group=cg)
            else:
                add_condition_to_group(condition=condition, group=condition_group)
        else:
            if condition:
                if type(condition) == list:
                    for c in condition:
                        add_global_condition(c)
                else:
                    add_global_condition(condition)

    def add_authoritative_condition(self, condition):
        """."""
        self.__authoritative_condition = str(condition)

    def add_tags(self, tags: Union[List[str], str]):
        """."""
        if type(tags) == list:
            self.tags.extend(tags)
        elif type(tags) == str:
            self.tags.append(tags)

    def add_strings(
        self,
        string: str,
        modifiers=False,
        identifier: Union[bool, str] = False,
        condition: Union[str, bool] = False,
        condition_group=False,
        default_boolean=False,
        string_type=False,
        comment=False,
        parent_group=False,
        condition_modifier=False,
    ):
        """."""

        def process_string_condition(
            condition,
            identifier,
            condition_group,
            default_boolean,
            parent_group,
            condition_modifier,
        ):

            if type(condition) == list:
                for i in range(len(condition)):
                    condition[i] = condition[i].replace(
                        self.identifier_template, identifier
                    )
            else:
                condition = condition.replace(self.identifier_template, identifier)

            self.add_condition(
                condition=condition,
                condition_group=condition_group,
                default_boolean=default_boolean,
                parent_group=parent_group,
                condition_modifier=condition_modifier,
            )

        string_template = deepcopy(self.__string_struct)

        if identifier is False:
            identifier = self.default_identifier

        if not identifier:
            for identifier in generate_identifier():
                if identifier not in self.used_identifiers:
                    break
            else:
                raise ValueError("Unknown identifier")

        self.used_identifiers.append(identifier)
        string_template["identifier"] = identifier

        string_template["strings"] = string
        string_template["condition_group"] = condition_group
        string_template["default_boolean"] = default_boolean

        if condition is not False:
            if condition is True:
                # Use the default condition
                string_template["condition"] = "%s ($%s*)" % (
                    self.default_str_condition,
                    identifier,
                )
            else:
                string_template["condition"] = condition

            process_string_condition(
                condition=string_template["condition"],
                identifier=identifier,
                condition_group=condition_group,
                default_boolean=default_boolean,
                parent_group=parent_group,
                condition_modifier=condition_modifier,
            )

        if modifiers is not False:
            string_template["modifiers"] = modifiers

        if comment is not False:
            string_template["comment"] = comment

        if string_type is not False:
            string_template["type"] = str(string_type)
        else:
            string_template["type"] = "str"

        self._strings.append(string_template)

    def add_regex(
        self,
        regex,
        modifiers=False,
        identifier=False,
        condition=False,
        condition_group=False,
        default_boolean=False,
        comment=False,
        parent_group=False,
        condition_modifier=False,
    ):
        """."""
        regex_template = "/%s/"

        if regex == list:
            for idx, _ in enumerate(regex):
                self.add_strings(
                    strings=regex_template % regex[idx],
                    modifiers=modifiers,
                    identifier=identifier,
                    condition=condition,
                    string_type="regex",
                    comment=comment,
                    condition_group=condition_group,
                    default_boolean=default_boolean,
                    parent_group=parent_group,
                    condition_modifier=condition_modifier,
                )
        else:
            self.add_strings(
                strings=regex_template % regex,
                modifiers=modifiers,
                identifier=identifier,
                condition=condition,
                string_type="regex",
                comment=comment,
                condition_group=condition_group,
                default_boolean=default_boolean,
                parent_group=parent_group,
                condition_modifier=condition_modifier,
            )

    def add_binary_strings(
        self,
        data,
        size_limit=False,
        modifiers=False,
        identifier=False,
        condition=False,
        condition_group=False,
        default_boolean=False,
        comment=False,
        parent_group=False,
        condition_modifier=False,
    ):
        """."""
        binary_template = "{%s}"

        if data == list:
            for idx, _ in enumerate(data):
                if size_limit:
                    data[idx] = binary_template % (
                        raw_to_hex(data[idx][0 : int(size_limit)])
                    )
                else:
                    data[idx] = binary_template % (raw_to_hex(data))

        else:
            if size_limit:
                data = "{%s}" % raw_to_hex(data[0 : int(size_limit)])
            else:
                data = "{%s}" % raw_to_hex(data)

        self.add_strings(
            strings=data,
            modifiers=modifiers,
            identifier=identifier,
            condition=condition,
            string_type="binary",
            comment=comment,
            condition_group=condition_group,
            default_boolean=default_boolean,
            parent_group=parent_group,
            condition_modifier=condition_modifier,
        )

    def add_binary_as_string(
        self,
        data,
        modifiers=False,
        identifier=False,
        condition=False,
        condition_group=False,
        default_boolean=False,
        comment=False,
        parent_group=False,
        condition_modifier=False,
    ):
        """."""
        binary_template = "{%s}"

        if data == list:
            for bin_str in data:
                self.add_strings(
                    strings=binary_template % bin_str,
                    modifiers=modifiers,
                    identifier=identifier,
                    condition=condition,
                    string_type="binary_str",
                    comment=comment,
                    condition_group=condition_group,
                    default_boolean=default_boolean,
                    parent_group=parent_group,
                    condition_modifier=condition_modifier,
                )

        else:
            self.add_strings(
                strings=binary_template % data,
                modifiers=modifiers,
                identifier=identifier,
                condition=condition,
                string_type="binary_str",
                comment=comment,
                condition_group=condition_group,
                default_boolean=default_boolean,
                parent_group=parent_group,
                condition_modifier=condition_modifier,
            )

    def process_strings(self):
        """."""

        def process_collections(str_obj):
            identifier_collections[identifier]["strings"].append(str_obj)

        def eval_string(
            t_ident,
            t_index,
            t_string,
            t_modifier=False,
            t_type=False,
            t_comment=False,
            ignore_index=False,
        ):
            ret_string = ""
            format_string = ""

            if ignore_index:
                t_index = ""

            if t_modifier:
                mtype = type(t_modifier)
                if mtype == list:
                    t_modifier = " ".join(t_modifier)

                if t_comment:
                    format_string = "$%s%s = %s %s //%s"
                    if type(t_comment) == list:
                        t_comment = " - ".join(t_comment)
                    return format_string % (
                        str(t_ident),
                        str(t_index),
                        t_string,
                        t_modifier,
                        t_comment,
                    )
                else:
                    format_string = "$%s%s = %s %s"
                    return format_string % (
                        str(t_ident),
                        str(t_index),
                        t_string,
                        t_modifier,
                    )
            else:
                if t_comment:
                    if type(t_comment) == list:
                        t_comment = " - ".join(t_comment)

                    format_string = "$%s%s = %s //%s"
                    return format_string % (
                        str(t_ident),
                        str(t_index),
                        t_string,
                        t_comment,
                    )
                else:
                    format_string = "$%s%s = %s"
                    return format_string % (str(t_ident), str(t_index), t_string)

        identifier_collections = dict()
        final_strings = []

        if not self._strings:
            return ""

        string_structs = self._strings

        #::prime::#
        for struct in string_structs:
            identifier = str(struct["identifier"])
            identifier_collections[identifier] = {
                "strings": [],
                "conditions": [],
                "condition_group": struct["condition_group"],
                "default_boolean": struct["default_boolean"],
            }

        #::process::#
        for struct in string_structs:
            identifier = str(struct["identifier"])
            modifiers = struct["modifiers"]
            strings = struct["strings"]
            condition = struct["condition"]
            str_type = struct["type"]
            comment = struct["comment"]

            stype = type(strings)
            contype = type(condition)

            if stype == str:
                if (
                    str_type == "binary"
                    or str_type == "regex"
                    or str_type == "binary_str"
                ):
                    process_collections((strings, modifiers, str_type, comment))
                else:
                    # FIX: Escape characters in sequences
                    strings = strings.encode("unicode_escape").decode("utf-8")
                    translate = str.maketrans({'"': r"\""})
                    process_collections(
                        (
                            f'"{strings.translate(translate)}"',
                            modifiers,
                            str_type,
                            comment,
                        )
                    )

            elif stype == list:
                for string in strings:
                    if (
                        str_type == "binary"
                        or str_type == "regex"
                        or str_type == "binary_str"
                    ):
                        process_collections((string, modifiers, str_type, comment))
                    else:
                        process_collections(
                            ('"' + string + '"', modifiers, str_type, comment)
                        )
            #::history lesson: I typo'd and left 'strings' in the appended clause and troubleshooted for about an hour. D'oh.
            else:
                process_collections(
                    ('"' + str(strings) + '"', modifiers, str_type, comment)
                )

            if condition != "":

                if contype == str:
                    identifier_collections[identifier]["conditions"].append(condition)

                if contype == list:
                    for cd in condition:
                        identifier_collections[identifier]["conditions"].append(cd)

        #::uniq it::#
        for identifier, id_dict in identifier_collections.items():
            identifier_collections[identifier]["strings"] = id_dict["strings"]
            identifier_collections[identifier]["conditions"] = list(
                set(id_dict["conditions"])
            )

            #::get it on::#
            if len(id_dict["strings"]) > 1:
                for index in range(len(id_dict["strings"])):

                    pstring = id_dict["strings"][index][0]
                    modifier = id_dict["strings"][index][1]
                    stype = id_dict["strings"][index][2]
                    comment = id_dict["strings"][index][3]

                    pstype = type(pstring)

                    if pstype == str:
                        final_strings.append(
                            eval_string(
                                t_ident=identifier,
                                t_index=index,
                                t_string=pstring,
                                t_modifier=modifier,
                                t_type=stype,
                                t_comment=comment,
                            )
                        )

                    if pstype == list:
                        for tmp_string in pstring:
                            final_strings.append(
                                eval_string(
                                    t_ident=identifier,
                                    t_index=index,
                                    t_string=tmp_string,
                                    t_modifier=modifier,
                                    t_type=stype,
                                    t_comment=comment,
                                )
                            )

            elif len(id_dict["strings"]) == 1:

                pstring = id_dict["strings"][0][0]
                modifier = id_dict["strings"][0][1]
                stype = id_dict["strings"][0][2]
                comment = id_dict["strings"][0][3]

                final_strings.append(
                    eval_string(
                        t_ident=identifier,
                        t_index=False,
                        t_string=pstring,
                        t_modifier=modifier,
                        t_type=stype,
                        t_comment=comment,
                        ignore_index=True,
                    )
                )

        if len(final_strings) > 0:

            return "\tstrings:\n\t\t%s\n" % ("\n\t\t".join(final_strings))

        else:

            return False

    def proc_cond_str(self, cond_struct):

        if len(cond_struct["conditions"]) > 0:
            if cond_struct["modifier"]:
                group_format_str = "%s (%s)"
                return group_format_str % (
                    cond_struct["modifier"],
                    (
                        (" %s " % cond_struct["default_boolean"]).join(
                            cond_struct["conditions"]
                        )
                    ),
                )
            else:
                group_format_str = "(%s)"
                return group_format_str % (
                    (" %s " % cond_struct["default_boolean"]).join(
                        cond_struct["conditions"]
                    )
                )
        else:
            return False

    def process_conditions(self, condition_groups=False, prototype=False):
        """."""

        #::Added to prototype condition groups. Hacky.
        int_condition_groups = None
        int_conditions = None

        if prototype:
            int_condition_groups = self.__proto_condition_groups
            int_conditions = self.__proto_conditions
        else:
            int_condition_groups = self.__condition_groups
            int_conditions = self._conditions

        condition_format_str = "\tcondition:\n\t\t%s\n"

        #::Skip return from authoritity condition if we are prototyping
        if self.__authoritative_condition and not prototype:
            auth_type = type(self.__authoritative_condition)
            if auth_type == str:
                return condition_format_str % self.__authoritative_condition
            if auth_type == list:
                return condition_format_str % str(
                    " " + self.default_boolean + " "
                ).join(self.__authoritative_condition)

        if condition_groups and int_condition_groups:
            #::This section warrants a re-write of complex condition groups...
            #::Probably as B+ tree (and totally OBO)
            #::Stylistically, maintaining order of conditions appears paramount,
            #::the code was already too deep to change the game.
            #::
            #::...Springfield Rules! Down with Shelbyville!
            #::
            #::process groups with parents, initialize parents, read in reverse order
            #::since conditions groups are in an ordered structure, process in reverse
            #::to ensure all parents are initalized, excluding root node
            #::Leaf
            for name in reversed(int_condition_groups.keys()):
                group_struct = int_condition_groups[name]
                if group_struct["parent"] and not group_struct["children"]:
                    if type(group_struct["parent"]) == list:
                        for parent in group_struct["parent"]:
                            #::If our parent is a child (key 'parent' == True), then we add our condition to them
                            if int_condition_groups[parent]["parent"]:
                                self.add_condition(
                                    condition=self.proc_cond_str(group_struct),
                                    condition_group=parent,
                                    prototype=prototype,
                                )
                    else:
                        if int_condition_groups[group_struct["parent"]]["parent"]:
                            self.add_condition(
                                condition=self.proc_cond_str(group_struct),
                                condition_group=group_struct["parent"],
                                prototype=prototype,
                            )

            #::Internal
            for name in reversed(int_condition_groups.keys()):
                group_struct = int_condition_groups[name]
                if group_struct["parent"] and group_struct["children"]:
                    if type(group_struct["parent"]) == list:
                        for parent in group_struct["parent"]:
                            #::If our parent is a child (key 'parent' == True), then we add our condition to them
                            if int_condition_groups[parent]["parent"]:
                                self.add_condition(
                                    condition=self.proc_cond_str(group_struct),
                                    condition_group=parent,
                                    prototype=prototype,
                                )
                    else:
                        if int_condition_groups[group_struct["parent"]]["parent"]:
                            self.add_condition(
                                condition=self.proc_cond_str(group_struct),
                                condition_group=group_struct["parent"],
                                prototype=prototype,
                            )

            #::Root
            for name, group_struct in int_condition_groups.items():
                #::iterate through our children
                if group_struct["children"]:
                    for child in group_struct["children"]:
                        #::if we have no parent, add children conditions to ourselves
                        if not group_struct["parent"]:
                            self.add_condition(
                                condition=self.proc_cond_str(
                                    int_condition_groups[child]
                                ),
                                condition_group=name,
                                prototype=prototype,
                            )

            #::If we are root node (no parents) and not a virtual group, add us as condition
            if int_condition_groups:
                for name, group_struct in int_condition_groups.items():
                    if not group_struct["virtual"] and not group_struct["parent"]:
                        self.add_condition(
                            condition=self.proc_cond_str(group_struct),
                            prototype=prototype,
                        )

        #::If we are in prototype mode, no need to continue
        if prototype:
            return

        if self._conditions:
            if len(self._conditions) >= 1:
                tmp_conditions = []
                for cond in self._conditions:
                    tmp_conditions.append(cond)
                return condition_format_str % str(
                    " " + self.default_boolean + " \n\t\t"
                ).join(tmp_conditions)
        else:
            return condition_format_str % self.default_condition

    def process_meta(self):
        """."""

        if self._meta:
            output: str = "\tmeta:\n"
            for key, value in self._meta.items():
                output += f'\t\t{key} = "{value}" \n'

            return output

        return ""

    def process_tags(self):

        if self.tags:
            return " : %s" % " ".join(self.tags)
        else:
            return ""

    def process_scope(self):

        scope = []

        if self.private_rule:
            scope.append("private")

        if self.global_rule:
            scope.append("global")

        if scope:
            return "%s " % " ".join(scope)
        else:
            return ""

    def ret_complete_rule(self, rule_name, condition, tags, scope, meta="", strings=""):
        """."""

        return (
            f"{scope}rule {rule_name} {tags} {{\n"
            f"{meta}\n"
            f"{strings}\n"
            f"{condition}\n"
            f"}}"
        )

    def build_rule(self, condition_groups=False) -> str:
        """."""
        tmp_condition = self.process_conditions(condition_groups=condition_groups)

        tmp_strings = self.process_strings()
        tmp_meta = self.process_meta()
        tmp_tags = self.process_tags()
        tmp_scope = self.process_scope()

        if tmp_condition or tmp_strings:
            kwargs = {
                "rule_name": self.name,
                "condition": tmp_condition,
                "meta": tmp_meta,
                "strings": tmp_strings,
                "tags": tmp_tags,
                "scope": tmp_scope,
            }
            rule = self.ret_complete_rule(**kwargs)
            return rule

        else:
            raise qsig.sig.exc.YaraToolException(
                "No Strings Or Conditions In Rule, Check Rule"
            )


class RuleFile:
    def __init__(
        self,
        imports: MaybeMultiple = None,
        includes: MaybeMultiple = None,
        default_meta: Optional[Dict] = None,
        prefix: str = "",
    ):

        self._rules: List[Rule] = []

        self._imports: List[str] = []
        self._includes: List[str] = []

        self._description: str = ""

        if imports is not None:
            self.add_import(imports)

        if includes is not None:
            self.add_include(includes)

        self._default_meta = {}
        if default_meta is not None:
            self._default_meta.update(default_meta)

        self._prefix: str = sanitize_string(prefix) + "_" if prefix else ""

    def add_description(self, description: str):
        self._description = description

    def add_import(self, imports: Multiple):
        """."""
        if isinstance(imports, str):
            imports = [imports]

        if any(x in self._imports for x in imports):
            raise ValueError("Imports must be unique")

        self._imports.extend(imports)

    def add_include(self, includes: Multiple):
        """."""
        if isinstance(includes, str):
            includes = [includes]

        if any(x in self._includes for x in includes):
            raise ValueError("Includes must be unique")

        self._includes.extend(includes)

    def create_rule(self, name: str, *args, suffix: str = "", **kwargs) -> Rule:

        meta = deepcopy(self._default_meta)
        meta.update(kwargs.pop("meta", {}))

        # Reduce the name of the rule if more > 100 because the limit in YARA in 128
        # and we want to keep some space for the suffix __common or/ __fix
        name = self._prefix + name[: 128 - len(self._prefix + suffix)] + suffix

        self._rules.append(Rule(*args, name=name, meta=meta, **kwargs))
        return self._rules[-1]

    def build_rules(self, condition_groups: bool = False) -> str:
        def create_comment(comment: str) -> str:
            return f"/* {comment} */\n"

        def process_list(str_list: List[str], keyword: str) -> str:
            ret: str = "\n".join(f'{keyword} "{s}"' for s in str_list)
            return ret + "\n" if ret != "" else ""

        output_string: str = ""

        output_string += process_list(self._imports, "import")
        output_string += process_list(self._includes, "include")

        if self._description:
            output_string += create_comment(self._description)

        for rule in self._rules:
            output_string += "\n" + rule.build_rule(condition_groups) + "\n"

        return output_string

    def compile(self) -> bytes:
        rules = self.build_rules()
        try:
            rule = yara.compile(source=rules)
        except yara.SyntaxError:
            raise qsig.sig.exc.YaraToolException("Unable to compile the rule")

        buffer: io.BytesIO = io.BytesIO()
        try:
            rule.save(file=buffer)
        except yara.Error:
            return b""

        buffer.seek(0)
        return buffer.read()

    def __str__(self) -> str:
        return self.build_rules()

    def save(self, output_file: os.PathLike) -> None:
        with open(output_file, "w") as file:
            file.write(str(self))
