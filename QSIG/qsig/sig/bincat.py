from __future__ import annotations
import collections
import configparser
import logging
import functools
import os
import pathlib
import pickle
import subprocess
import tempfile
from typing import Optional, Union, Tuple, List, Dict, Type, overload

import quokka.analysis
import quokka.analysis.calling_convention as cc
import quokka.analysis.env
import quokka.block
import quokka.exc
import quokka.function
import quokka.program
import quokka.utils
import quokka.types


import qsig.sig


logger: logging.Logger = logging.getLogger(__name__)
"""Logger instance"""

X64_GPR = ["rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi", "rsp"] + [
    "r%d" % d for d in range(8, 16)
]
"""Registers used in X64"""

X86_GPR = ["eax", "ecx", "edx", "ebx", "ebp", "esi", "edi", "esp"]
"""Registers used in x86"""


def transform_enum(enum_list: List) -> List[str]:
    """Transform an enum into a liste of enum name"""
    return [x.name for x in enum_list]


def get_platform_specific(
    platform: quokka.analysis.Platform, address_size: int
) -> Dict[str, Union[str, int]]:
    """Returns the memory model for BinCAT

    Note: Values have been riped from BinCAT.

    Args:
        platform: Platform targetted
        address_size: Size of a memory address

    Returns:
        An array of registers name/value
    """
    mapping = {
        quokka.analysis.Platform.LINUX: {
            32: {
                "mem_model": "flat",
                "GDT[0]": 0x0000000000000000,
                "GDT[1]": 0x0000000000000000,
                "GDT[2]": 0x0000000000000000,
                "GDT[3]": 0x0000000000000000,
                "GDT[4]": 0x0000000000000000,
                "GDT[5]": 0x0000000000000000,
                "GDT[6]": 0x00CFF3000000FFFF,
                "GDT[7]": 0x0000000000000000,
                "GDT[8]": 0x0000000000000000,
                "GDT[9]": 0x0000000000000000,
                "GDT[10]": 0x0000000000000000,
                "GDT[11]": 0x0000000000000000,
                "GDT[12]": 0x00CF9A000000FFFF,
                "GDT[13]": 0x00CF93000000FFFF,
                "GDT[14]": 0x00CFFA000000FFFF,
                "GDT[15]": 0x00CFF3000000FFFF,
                "GDT[16]": 0xC1008B598CC0206B,
                "GDT[17]": 0x0000000000000000,
                "GDT[18]": 0x00409A000000FFFF,
                "GDT[19]": 0x00009A000000FFFF,
                "GDT[20]": 0x000092000000FFFF,
                "GDT[21]": 0x0000920000000000,
                "GDT[22]": 0x0000920000000000,
                "GDT[23]": 0x00409A000000FFFF,
                "GDT[24]": 0x00009A000000FFFF,
                "GDT[25]": 0x004092000000FFFF,
                "GDT[26]": 0x00CF92000000FFFF,
                "GDT[27]": 0x00CF92000000FFFF,
                "GDT[28]": 0xC140915F7C800018,
                "GDT[29]": 0x0000000000000000,
                "GDT[30]": 0x0000000000000000,
                "GDT[31]": 0xC1008958E000206B,
                "cs": 0x73,
                "ds": 0x7B,
                "ss": 0x7B,
                "es": 0x7B,
                "fs": 0x00,
                "gs": 0x33,
            },
            64: {
                "GDT[0]": 0x0000000000000000,
                "GDT[1]": 0x00CF9B000000FFFF,
                "GDT[2]": 0x00AF9B000000FFFF,
                "GDT[3]": 0x00CF93000000FFFF,
                "GDT[4]": 0x00CFFB000000FFFF,
                "GDT[5]": 0x00CFF3000000FFFF,
                "GDT[6]": 0x00AFFB000000FFFF,
                "GDT[8]": 0xFB008B6048C02087,
                "GDT[9]": 0x00000000FFFF8F4B,
                "GDT[15]": 0x0040F50000000000,
                "cs": 0x33,
                "ss": 0x2B,
                "ds": 0,
                "es": 0,
                "fs": 0,
                "gs": 0,
                "fs_base": 0x800000,
                "gs_base": 0x900000,
            },
        },
        quokka.analysis.Platform.WINDOWS: {
            32: {
                "mem_model": "flat",
                "GDT[1]": 0x00CF9B000000FFFF,
                "GDT[2]": 0x00CF93000000FFFF,
                "GDT[3]": 0x00CFFB000000FFFF,
                "GDT[4]": 0x00CFF3000000FFFF,
                "GDT[5]": 0x80008B04200020AB,
                "GDT[6]": 0xFFC093DFF0000001,
                "GDT[7]": 0x0040F30000000FFF,
                "GDT[8]": 0x0000F2000400FFFF,
                "cs": 0x1B,
                "ds": 0x23,
                "ss": 0x23,
                "es": 0x23,
                "fs": 0x3B,
                "gs": 0x00,
            },
            64: {
                "GDT[0]": 0x00000000000000001,
                "GDT[1]": 0x0000000000000000,
                "GDT[2]": 0x00209B0000000000,
                "GDT[3]": 0x0040930000000000,
                "GDT[4]": 0x00CFFB000000FFFF,
                "GDT[5]": 0x00CFF3000000FFFF,
                "GDT[6]": 0x0020FB0000000000,
                "GDT[8]": 0xEC008BC520000067,
                "GDT[9]": 0x00000000FFFFF802,
                "GDT[10]": 0x0040F30000003C00,
                "cs": 0x33,
                "ss": 0x2B,
                "ds": 0x2B,
                "es": 0x2B,
                "fs": 0x53,
                "gs": 0x2B,
                "fs_base": 0x800000,
                "gs_base": 0x900000,
            },
        },
    }

    return mapping.get(platform, {}).get(address_size)


def get_registers_with_state(
    arch: Type[quokka.analysis.arch.quokkaArch],
) -> List[Tuple[str, str, str, str]]:
    """Find the registers associated with a state

    This method prepares the state for BinCAT by setting every register with the less
    information possible.

    The value mask is ["name", "value", "topmask", "taintmask].
    See BinCAT documentations for more help.

    TODO(dm):
        Integrate with archinfo

    Args:
        arch: Architecture

    Raises:
        NonImplementedError when the architecture is not known

    Returns:
        A list of registers values-array
    """
    flags_list: List[str] = [
        "cf",
        "pf",
        "af",
        "zf",
        "sf",
        "tf",
        "if",
        "of",
        "nt",
        "rf",
        "vm",
        "ac",
        "vif",
        "vip",
        "id",
    ]
    regs: List[Tuple[str, str, str, str]] = []
    if arch == quokka.analysis.arch.ArchX86:
        for name in X86_GPR:
            regs.append((name, "0", "0xFFFFFFFF", ""))

        regs.append(("esp", "0xb8001000", "", ""))

        for name in flags_list:
            regs.append((name, "0", "1", ""))
        regs.append(("df", "0", "", ""))
        regs.append(("iopl", "3", "", ""))

    elif arch == quokka.analysis.arch.ArchX64:
        for name in X64_GPR:
            regs.append((name, "0", "0xFFFFFFFFFFFFFFFF", ""))

        regs.append(("rsp", "0xb8001000", "", ""))

        for name in flags_list:
            regs.append((name, "0", "1", ""))

        regs.append(("df", "0", "", ""))
        regs.append(("iopl", "3", "", ""))

    elif arch in [
        quokka.analysis.arch.ArchARM,
        quokka.analysis.arch.ArchARMThumb,
    ]:
        for i in range(13):
            regs.append(("r%d" % i, "0", "0xFFFFFFFF", ""))
        regs.append(("sp", "0xb8001000", "", ""))
        regs.append(("lr", "0x0", "", ""))
        regs.append(("pc", "0x0", "", ""))
        regs.append(("n", "0", "1", ""))
        regs.append(("z", "0", "1", ""))
        regs.append(("c", "0", "1", ""))
        regs.append(("v", "0", "1", ""))
        regs.append(("t", "0", "", ""))

    elif arch == quokka.analysis.arch.ArchARM64:
        for i in range(31):
            regs.append(("x%d" % i, "0", "0xFFFFFFFFFFFFFFFF", ""))
        regs.append(("sp", "0xb8001000", "", ""))
        for i in range(32):
            regs.append(("q%d" % i, "0", "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", ""))
        regs.append(("n", "0", "1", ""))
        regs.append(("z", "0", "1", ""))
        regs.append(("c", "0", "1", ""))
        regs.append(("v", "0", "1", ""))
        regs.append(("xzr", "0", "", ""))
    else:
        raise NotImplementedError("Unsupported arch")

    return regs


@overload
def get_architecture_name(arch: str) -> Type[quokka.analysis.arch.quokkaArch]:
    ...


@overload
def get_architecture_name(arch: Type[quokka.analysis.arch.quokkaArch]) -> str:
    ...


def get_architecture_name(
    arch: Union[Type[quokka.analysis.arch.quokkaArch], str]
) -> Union[Type[quokka.analysis.arch.quokkaArch], str]:
    """
    Translate an architecture representation between BinCAT and quokka

    Args:
        arch: Either a quokkaArch or a string coming from bincat

    Returns:
        The associated value
    """
    mapping = {
        quokka.analysis.arch.ArchX64: "x64",
        quokka.analysis.arch.ArchX86: "x86",
        quokka.analysis.arch.ArchARM: "armv7",
        quokka.analysis.arch.ArchARM64: "armv8",
        quokka.analysis.arch.ArchARMThumb: "armv7",
    }
    try:
        return mapping[arch]  # type: ignore
    except KeyError:
        for arch_cls, arch_str in mapping.items():
            if arch_str == arch:
                return arch_cls
        else:
            raise KeyError


@functools.lru_cache(maxsize=8)
def find_bincat(cmd: str) -> bool:
    """Search if BinCAT executable is in path

    Args:
        cmd: Name of the command

    Returns:
        boolean
    """
    try:
        subprocess.check_call(
            [cmd, "--help"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", "")},
            timeout=1,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        logger.info("Did not find BinCAT with command %s", cmd)
        return False

    return True


class CFA:
    """Results from a BinCAT run.

    BinCAT results are stored in an INI file format. This class loads the results and
    parses them.

    Args:
        filename: Path towards the result file

    Attributes:
        addr_nodes: Mapping from node address to node id
        edges: A mapping from src node to list of destination nodes
        nodes: A mapping from node id to nodes
        taintsrcs: Mapping from taint sources to their representation
        arch: Architecture value

    """

    def __init__(self, filename: pathlib.Path):
        """Constructor"""
        self.addr_nodes: Dict[int, int] = {}
        self.edges: collections.defaultdict = collections.defaultdict(list)

        self.nodes: Dict[int, Node] = {}
        self.taintsrcs: Dict[int, str] = {}

        config: configparser.RawConfigParser = configparser.RawConfigParser()
        try:
            config.read(filename)
        except configparser.ParsingError as e:
            logger.exception(e)
            raise qsig.sig.BincatException("Failed to parse config")

        if len(config.sections()) == 0:
            raise qsig.sig.BincatException("Output of BinCAT is empty")

        arch_str: str = config.get("program", "architecture")
        self.arch: Type[
            quokka.analysis.arch.quokkaArch
        ] = get_architecture_name(arch_str)
        self.mem_sz: int = int(config.get("program", "mem_sz"))

        # Parse taint source first
        max_taint_id = 0
        if config.has_section("taint sources"):
            for src_id, src_name in config.items("taint sources"):
                self.taintsrcs[int(src_id)] = src_name
                max_taint_id = max(int(src_id), max_taint_id)
        else:
            raise qsig.sig.BincatException("No taint sources were found")

        if config.has_section("edges"):
            for _, edge in config.items("edges"):
                src, dst = edge.split(" -> ")
                self.edges[src].append(dst)

        for node_section in config.sections():
            if node_section.startswith("node = ") and "unrel" not in node_section:
                node_id = int(node_section[7:])
                node = Node.parse(node_id, dict(config.items(node_section)))
                self.addr_nodes[node.address] = node.node_id
                self.nodes[node.node_id] = node

    def __getitem__(self, node_id) -> Optional[Node]:
        """
        Returns Node at provided node_id if it exists, else None.
        """
        if type(node_id) is int:
            node_id = str(node_id)
        return self.nodes.get(node_id, None)

    def node_from_addr(self, addr: int) -> Node:
        """Return a node from an address

        Args:
            addr: Address of the node

        Raises:
            KeyError if no node is found

        Returns:
            A Node object
        """
        return self.nodes[self.addr_nodes[addr]]


class Node:
    """
    Stores node data for a given node_id.

    1 or more Unrel may be stored, each containing registers addresses and register
    types

    Attributes:

    Args:
        node_id: Node id
        address: Node address
        final: is the node final (i.e. no successor)
        taint_srcs: ids of the taints

    Attributes:
        node_id: Node id
        address: Node address
        final: is the node final (i.e. no successor)
        taint_srcs: ids of the taints
    """

    def __init__(self, node_id: int, address: int, final: bool, taint_srcs: List[int]):
        """Constructor"""
        self.address: int = address
        self.node_id: int = node_id
        self.final: bool = final
        self.taint_srcs: List[int] = taint_srcs

    @property
    def tainted(self) -> bool:
        """Is the node tainted"""
        return self.taint_srcs != []

    @classmethod
    def parse(cls, node_id: int, outputkv: Dict[str, str]) -> Node:
        """Creates a node from a dict of values

        Args:
            node_id: Node ID
            outputkv: list of (key, value) tuples for each property set by
            the analyzer at this EIP

        Returns:
            A newly created node
        """

        address = int(outputkv.pop("address", "0"), 16)
        final = outputkv.pop("final", None) == "true"
        taint_src = Node.clean_taint(outputkv.pop("tainted"))
        new_node = Node(node_id, address, final, taint_src)
        return new_node

    @staticmethod
    def clean_taint(taint_str: str) -> List[int]:
        """Clean the taint source from a list of str to a list of int"""
        tainted_srcs = taint_str.split(",")

        taints = []
        for taint_src in tainted_srcs:
            if taint_src in ["", "?", "U"]:
                continue
            taint_src = taint_src.strip()
            if taint_src.startswith("t-"):
                taint_src = taint_src[2:]
            else:
                raise qsig.sig.BincatException("Taint source is misformed")
            taints.append(int(taint_src))

        return taints

    def __repr__(self) -> str:
        """Class representation"""
        return f"Node at address 0x{self.address:x} (node={self.node_id})"


class OrderedConfigParser(configparser.RawConfigParser):
    """ConfigParser for BinCAT configuration

    Order matter in BinCAT configuration so we override the writer to print section in
    the correct orders as specified in the `_sections` variable.

    See: configparser.RawConfigParser for documentation for the other parameters
    """

    def write(
        self,
        fp,  # TODO(dm) find appropriate type hint
        space_around_delimiters: bool = True,
        order: Optional[List[str]] = None,
    ) -> None:
        if space_around_delimiters:
            d = " {} ".format(self._delimiters[0])
        else:
            d = self._delimiters[0]
        if self._defaults:
            self._write_section(fp, self.default_section, self._defaults.items(), d)

        if order is None:
            order = list(self._sections)
        else:
            for section in order:
                if section not in self._sections:
                    raise configparser.NoSectionError(section=section)

            for section in self._sections:
                if section not in order:
                    order.append(section)

        for section in order:
            self._write_section(fp, section, self._sections[section].items(), d)


class BincatConfig:
    """Configuration for BinCAT

    Attributes:
        config: An OrderedConfigParser
        env: A quokka environment
        work_dir: Path to the work directory
        ini_file: Path to the config file
        out_file: Path to the output file
        log_file: Path to the log file
        skipped_func: Which address should be skipped
        args_count: How many arguments for the function
    """

    def __init__(self):
        self.config: OrderedConfigParser = OrderedConfigParser()

        # Prevent from changing the case of the option
        self.config.optionxform = lambda option: option

        self.env: Optional[quokka.analysis.env.Environment] = None

        self.work_dir: pathlib.Path = pathlib.Path(tempfile.mkdtemp(prefix="qsig_"))
        self.ini_file: Optional[pathlib.Path] = None
        self.out_file: Optional[pathlib.Path] = None
        self.log_file: Optional[pathlib.Path] = None

        self.skipped_func: List[int] = []
        self.args_count: int = 0

    @property
    def program(self) -> Optional[pathlib.Path]:
        """Path of the analyzed program"""
        try:
            program = self.config.get("program", "filepath")
            return pathlib.Path(program.replace('"', ""))
        except (configparser.NoOptionError, configparser.NoSectionError):
            return None

    def set_binary(self, program: quokka.Program) -> None:
        """Set a binary to be analyzed by BinCAT

        This overrides any previous setting for another program (which is good).

        Args:
            program: Exported version of the program
        """
        self.env = quokka.analysis.env.Environment(
            platform=quokka.analysis.Platform.LINUX, arch=program.arch
        )

        self.program_section(program, self.env)
        self.set_architecture(self.env)
        self.set_initial_state(program)

        try:
            self.config.add_section("analyzer")
        except configparser.DuplicateSectionError:
            pass

        self.config["analyzer"] = {
            "unroll": 5,
            "function_unroll": 50,
            "loglevel": 2,  # TODO (function of debug)
            "ini_version": 4,
            "analysis": "forward_binary",
            "analysis_ep": 0,
            "store_marshalled_cfa": "false",
            "cut": 0,
            "ignore_unknown_relocations": "true",
            "fun_skip": "",
        }

        # Prepare section for argument
        self.add_arguments(self.env)

    def set_function(
        self, function: Union[quokka.function.Function, quokka.function.Chunk]
    ) -> bool:
        """This prepares the analysis for a specific function

        This must be called after set_binary and will keep all binary related settings.

        Args:
            function: Function to analyze

        Returns:
            boolean for success
        """

        if logger.getEffectiveLevel() <= logging.DEBUG:
            self.work_dir = pathlib.Path(tempfile.mkdtemp(prefix="qsig_"))

        # Reset directories
        self.ini_file = self.work_dir / "config.ini"
        self.out_file = self.work_dir / "out.ini"
        self.log_file = self.work_dir / "analyzer.log"

        self.function_analyzer()

        # Set function skip
        self.skip_calls(function)

        # Set boundaries
        self.set_entrypoint(function.start)

        # We want to cut at every block without a successor
        cut_addresses: List[int] = []
        for node in function.graph:
            if function.graph.out_degree(node) == 0 or (
                function.graph.out_degree(node) == 1
                and next(function.graph.successors(node), 0) == node
            ):
                block = function.get_block(node)
                cut_addresses.append(max(block._raw_dict))

        # Set cut addresses: if its the same as the function start, abort early
        has_cut = self.set_cut(cut_addresses, function.start)
        if has_cut is False:
            return False

        # Add CFG information
        self.add_cfg(function, self.env.arch.inst_pointer.name.lower())

        # FIX: For ARM, if the first instruction is thumb, tell BinCAT
        if self.env.arch in [
            quokka.analysis.arch.ArchARM,
            quokka.analysis.arch.ArchARMThumb,
        ]:
            instruction = function.get_instruction(function.start)
            self.config.set("state", "reg[t]", "1" if instruction.thumb else "0")

        return True

    # Functions dependent config
    def function_analyzer(self) -> None:
        """Prepare the config for the function analyzer"""
        out_marshall = (self.work_dir / "cfaout.marshal").as_posix()
        in_marshall = (self.work_dir / "cfain.marshal").as_posix()
        headers = (self.work_dir / "no_headers.no").as_posix()

        options = {
            "out_marshalled_cfa_file": f'"{out_marshall}"',
            "headers": f'"{headers}"',
            "in_marshalled_cfa_file": f'"{in_marshall}"',
        }

        for key, value in options.items():
            self.config.set("analyzer", key, value)

    def set_entrypoint(self, entry_addr: int) -> None:
        """Assign the entry point for analysis"""
        self.config.set("analyzer", "analysis_ep", f"0x{entry_addr:x}")

    def set_cut(self, cut_addr: List[int], function_start: Optional[int] = None) -> bool:
        """Assign the cut values (e.g. values where it should stop)

        Args:
            cut_addr: Stop address list
            function_start: The address of the function start

        Returns:
            False if the cut address is the same as the function start (function with 1 instruction)
        """

        if len(cut_addr) == 1 and cut_addr[0] == function_start:
            return False

        cut_str: str = ",".join(f"0x{addr:x}" for addr in cut_addr)
        self.config.set("analyzer", "cut", cut_str)

        return True

    def skip_calls(self, function: quokka.function.Function) -> None:
        """Prepare BinCAT to skip calls

        In QSig, we skip every call made to external function. This method finds every
        calls and add them to the skipping list.
        Moreover, it prepare a taint value for each call.

        Args:
            function: Function
        """
        return_value: str = f"0?0x{2**function.program.address_size - 1:x}"

        self.skipped_func: List[quokka.types.AddressT] = []
        for call_target in set(function.calls):
            self.skipped_func.append(call_target.start)

        if self.skipped_func:
            self.config.set(
                "analyzer",
                "fun_skip",
                ",".join(
                    f"0x{start:x}(1, {return_value}!TAINT_ALL)"
                    for start in self.skipped_func
                ),
            )
        else:
            self.config.remove_option("analyzer", "fun_skip")

    def add_cfg(
        self,
        function: Union[quokka.function.Function, quokka.function.Chunk],
        instruction_pointer: str,
    ) -> None:
        """Tell BinCAT about the CFG of the function

        When a function is complex enough, BinCAT is lost when recovering the CFG.
        This method transfer information from IDA to BinCAT.

        Args:
            function: Function
            instruction_pointer: Name of the instruction pointer
        """

        # FIX: reset CFG config for every config
        self.config.remove_section("cfg")
        self.config.add_section("cfg")

        for node in function.graph:
            if function.graph.out_degree(node) > 2:
                successors = ",".join(
                    f"0x{x:x}" for x in function.graph.successors(node)
                )

                block = function.get_block(node)
                last_instruction = block.last_instruction
                try:
                    reg_name = last_instruction.cs_inst.regs_read[0].name.lower()
                except IndexError:
                    # Fallback to the instruction pointer
                    reg_name = instruction_pointer

                self.config.set(
                    "cfg",
                    f"0x{last_instruction.address:x}",
                    f"{reg_name}({successors})",
                )

    # Program dependent config
    def program_section(
        self, program: quokka.Program, env: quokka.analysis.env.Environment
    ) -> None:
        """Prepare the config for program related values

        Args:
            program: Program
            env: quokka Environment
        """
        try:
            self.config.add_section("program")
        except configparser.DuplicateSectionError:
            pass

        allowed_cc: List[Type[cc.CallingConvention]] = [
            cc.SystemVAMD,
            cc.MicrosoftAMD64,
            cc.ARMCC,
            cc.Stdcall,
            cc.CCdecl,
            cc.Fastcall,
            cc.ARM64CC,
        ]

        calling_convention = cc.Stdcall.name
        if env.calling_convention in allowed_cc:
            calling_convention = env.calling_convention.name
        else:
            logger.error(
                "Missing support for %s, fallback to %s",
                env.calling_convention,
                calling_convention,
            )

        mem_size: str = f"{program.address_size}"

        self.config["program"] = {
            "mode": "protected",
            "call_conv": calling_convention,
            "mem_sz": mem_size,
            "op_sz": mem_size,  # stack width?
            "stack_width": mem_size,  # stack width?
            "architecture": get_architecture_name(env.arch),
            "filepath": f'"{program.executable.exec_file.absolute()!s}"',
            "format": "elfobj"
            if program.executable.exec_file.suffix == ".o"
            else "elf",
        }

    def set_architecture(self, env: quokka.analysis.env.Environment) -> None:
        """Set the architecture and its specific function

        TODO(dm): check why only for x86

        Args:
            env: Environment
        """
        section_name = None
        if env.arch in [
            quokka.analysis.arch.ArchX86,
            quokka.analysis.arch.ArchX64,
        ]:
            section_name = get_architecture_name(env.arch)

        if section_name and not self.config.has_section(section_name):
            self.config.add_section(section_name)

            for key, value in get_platform_specific(
                env.platform, env.arch.address_size
            ).items():
                self.config.set(section_name, key, str(value))

    def add_arguments(self, env: quokka.analysis.env.Environment):
        """Add argument, their taint, and their specific address range.

        Each argument has a distinct memory space so we can dereference from it and
        still having the same taint value.

        Args:
            env: Environment to recover the CC
        """
        try:
            self.config.add_section("sections")
        except configparser.DuplicateSectionError:
            pass

        self.args_count: int = len(env.calling_convention.argument_registers)

        for register in env.calling_convention.argument_registers:
            try:
                value_str = self.config.get("state", f"reg[{register.name.lower()}]")
            except configparser.NoOptionError:
                raise qsig.sig.BincatException("Missing register in state config")

            value, top, taint = self.split_value(value_str)
            self.config.set(
                "state",
                f"reg[{register.name.lower()}]",
                self.compose_value(value, top, "TAINT_ALL"),
            )

        section_addr: int = 0xFFFF0000
        section_size: int = 0x1000
        for i in range(0, self.args_count):
            section_str = f"0x{section_addr:x}, 0x{section_size:x}, 0x{section_addr:x}, 0x{section_size:x}"
            self.config.set("sections", f"section[arg{i}]", section_str)
            section_addr += section_size

            self.config.set(
                "state", f"mem[0x{section_addr:x}*0x{section_size:x}]", "|00|?0xFF"
            )

    def set_initial_state(self, program: quokka.Program) -> None:
        """Prepare the initial state

        The initial state is the most unconstrained possible to perform the deepest
        possible analysis

        Args:
            program: Program
        """
        try:
            self.config.add_section("state")
        except configparser.DuplicateSectionError:
            pass

        # Set registers
        for registers_array in get_registers_with_state(program.arch):
            reg_name, reg_value, top_value, taint = registers_array
            self.config.set(
                "state",
                f"reg[{reg_name}]",
                self.compose_value(reg_value, top_value, taint),
            )

        # Set memory
        self.config.set(
            "state", f"mem[0xb8000000*8192]", self.compose_value("|00|", "0xFF")
        )

    # General methods
    @staticmethod
    def compose_value(
        value: str, mask: Optional[str] = None, taint: Optional[str] = None
    ) -> str:
        """Compose a value for BinCAT"""
        value_str = f"{value}"
        if mask:
            value_str += f"?{mask}"
        if taint:
            value_str += f"!{taint}"

        return value_str

    @staticmethod
    def split_value(value_str: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Split a value from BinCAT"""

        values = value_str.split("?")

        value: str = values[0]
        top: Optional[str] = None
        taint: Optional[str] = None

        if "?" in value_str:
            if "!" in value_str:
                top, taint = values[1].split("!")
            else:
                top = values[1]

        return value, top, taint

    def write(self, *args, **kwargs):
        """Write the config"""
        # Fix: Force the writing of the analyzer section first
        self.config.write(*args, order=["analyzer", "program"], **kwargs)


class Bincat:
    """BinCAT wrapper

    Args:
        bincat_path: Optional. Path to BinCAT if not in PATH

    Attributes:
        config: BincatConfig instance
        cfa: CFA instance for results
        cmd: Path to the command or name of it
        result_file: Path to the cache of the results
        tainted_cmps: Comparisons mapping

    """

    def __init__(self, bincat_path: Optional[pathlib.Path] = None):
        """Constructor"""
        self.config: Optional[BincatConfig] = None
        self.cfa: Optional[CFA] = None

        self.cmd: str = "bincat"
        if bincat_path is not None:
            self.cmd = bincat_path.as_posix()

        # Search if we find BinCAT
        if not find_bincat(self.cmd):
            raise qsig.sig.BincatException("Missing bincat binary")

        # Cache system
        self.result_file: Optional[pathlib.Path] = None
        self.tainted_cmps: Dict[
            quokka.types.AddressT,
            Union[bool, Tuple[qsig.sig.LabelsCollection, List[qsig.sig.Condition]]],
        ] = {}

    def __del__(self) -> None:
        """Destructor"""
        self.save_tainted_cmps()

    def save_tainted_cmps(self) -> None:
        """Save the comparisons in `result_file`"""
        if self.result_file is None:
            return

        try:
            pickle.dump(self.tainted_cmps, open(self.result_file, "wb"))
        except pickle.PickleError:
            self.result_file.unlink()

    def load_tainted_cmps(self) -> None:
        """Load the cached comparisons if `result_file` exists"""
        self.tainted_cmps = {}
        if self.result_file is None:
            return

        try:
            self.tainted_cmps = pickle.load(open(self.result_file, "rb"))
        except (pickle.PickleError, FileNotFoundError):
            self.result_file = None

    def error_handling(self, log_file: pathlib.Path, level: str = "exception") -> None:
        """Print errors from BinCAT

        This method is useful to debug BinCAT runs.

        Args:
            log_file: Log file to search errors from
            level: Level of error to log
        """
        try:
            content = open(log_file).readlines()
        except FileNotFoundError:
            logger.error("Bincat failed and no log files was created.")
            return

        starts = ["[EXCEPTION]"]
        if level.lower() == "error":
            starts.append("[ERROR]")

        errors = []
        for index, line in enumerate(content):
            if "[ERROR]" in starts and line.startswith("[ERROR]"):
                errors.append(f"{line}")
            elif "[EXCEPTION]" in starts and line.startswith("[EXCEPTION]"):
                errors.append("{} {}".format(line.strip(), content[index + 1]))

        if errors:
            if self.config is not None:
                logger.error("BinCAT failure for config file %s", self.config.ini_file)
            else:
                logger.error("BinCAT failure for config file not loaded")

    def set_binary(
        self, program: quokka.Program, result_file: Optional[pathlib.Path] = None
    ) -> None:
        """Set a binary for a BinCAT analysis

        Checks if the program already set is the good one otherwise reset it.

        Args:
            program: Program to analyze
            result_file: Optional. A path to store the result of the analyses
        """
        if not self.config:
            self.config = BincatConfig()

        assert self.config is not None

        # Swap programs
        if self.config.program != program.executable.exec_file:
            # First, remove old state
            self.save_tainted_cmps()

            # Then load new state
            self.config.set_binary(program)
            self.result_file = result_file

            if self.result_file and self.result_file.is_file():
                self.load_tainted_cmps()

    def analyze_function(
        self, function: Union[quokka.function.Function, quokka.function.Chunk]
    ) -> bool:
        """Analyze a function

        Main method here:
            1/ sets the program into the config
            2/ sets the function
            3/ starts BinCAT and waits for results
            4/ parses the results

        Args:
            function: Function to analyze

        Returns:
            boolean for success
        """

        self.set_binary(function.program)
        assert self.config is not None

        result = self.config.set_function(function)
        if result is False:
            return False

        self.cfa = None

        with open(self.config.ini_file, "w") as file:
            self.config.write(file)

        cmd = [
            self.cmd,
            f"{self.config.ini_file!s}",
            f"{self.config.out_file!s}",
            f"{self.config.log_file!s}",
        ]

        logger.debug("Config is in %s", self.config.ini_file)

        try:
            subprocess.check_call(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=qsig.Settings.BINCAT_TIMEOUT,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            self.error_handling(self.config.log_file)
            return False

        self.cfa = CFA(self.config.out_file)
        return True

    def get_tainted_comparisons(
        self, function: Union[quokka.function.Function, quokka.function.Chunk]
    ) -> Tuple[
        quokka.types.AddressT, qsig.sig.LabelsCollection, List[qsig.sig.Condition]
    ]:
        """Get the tainted comparisons in the function

        Complex function here and results are cached inside the tainted_cmps mapping.
        If the result is not already computed then:
            1/ Get the list of comparison mnemonic for the architecture
            2/ Prepare the labels collections
            3/ For each instructions, if this is a comparison instruction, get the
                tainted elements and store them
            4/ Report statistics


        Args:
            function: Target function

        Returns:
            Function Address, Labels, Conditions
        """

        if function.start not in self.tainted_cmps:
            arch = function.program.arch
            compared_mnemonics = transform_enum(
                arch.compared_mnemonics
            )

            assert self.config is not None and self.cfa is not None
            labels = qsig.sig.LabelsCollection(self.config.skipped_func)

            comparisons: Dict = {}
            missed_cmps: int = 0
            total_instruction: int = 0
            missed_instruction: int = 0
            for instruction in function.instructions:

                total_instruction += 1
                try:
                    if instruction.address in self.cfa.addr_nodes:
                        missed_instruction += 1
                except quokka.exc.InstructionError:
                    continue

                inst_mnem = instruction.program.proto.mnemonics[
                    instruction.program.proto.instructions[
                        instruction.proto_index
                    ].mnemonic_index
                ]
                if (
                    quokka.analysis.Replacer.norm_mnemonic(inst_mnem)
                    in compared_mnemonics
                ):
                    try:
                        node = self.cfa.node_from_addr(instruction.address)
                    except KeyError:
                        missed_cmps += 1
                        continue

                    if node.tainted:
                        compared_elements = [labels[src] for src in node.taint_srcs]
                        comparisons[
                            instruction.address
                        ] = qsig.sig.Condition.from_bincat(
                            compared_elements, instruction, labels
                        )
                    else:
                        pass
                        # logger.debug('Comparison at address 0x%x is not tainted',
                        #              instruction.address)

            logger.debug(
                "Total coverage is %f (%d/%d)",
                missed_instruction / total_instruction,
                missed_instruction,
                total_instruction,
            )
            logger.debug("Missed %d comparisons during BinCAT coverage", missed_cmps)

            self.tainted_cmps[function.start] = labels, list(comparisons.values())

        labels_collection, conditions = self.tainted_cmps[function.start]
        return function.start, labels_collection, conditions


def get_condition_for_function(
    function: Union[quokka.function.Function, quokka.function.Chunk],
    bincat_interface: Optional[Bincat] = None,
    use_cache: bool = True,
) -> Optional[
    Tuple[
        quokka.types.AddressT, qsig.sig.LabelsCollection, List[qsig.sig.Condition]
    ]
]:
    """Get the conditions for a function using BinCAT.

    This is the main method of the module and orchestrates everything around.

    Args:
        function: Function to analyze
        bincat_interface: Optional. A BinCAT interface to use
        use_cache: Optional. Should we cache the results for enhanced performances

    Raises:
        BincatException if the analysis fails

    Returns:
        The address of the function, its label collection and its list of conditions
    """

    if bincat_interface is None:
        bincat_interface = Bincat()

    if (
        use_cache is False
        or bincat_interface.tainted_cmps.get(function.start, None) is None
    ):
        result = False
        try:
            result = bincat_interface.analyze_function(function)
        except qsig.sig.BincatException as e:
            logger.error("Unable to analyze function with BinCAT")
            # raise qsig.sig.BincatException(e)

        if result is False:
            bincat_interface.tainted_cmps[function.start] = False
            # raise qsig.sig.BincatException("Unable to analyze function")
        else:
            bincat_interface.get_tainted_comparisons(function)

    cached_result = bincat_interface.tainted_cmps.get(function.start)
    if cached_result is False:
        raise qsig.sig.BincatException("Unable to analyze function")
    else:
        return function.start, cached_result[0], cached_result[1]
