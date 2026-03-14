import os
from typing import Any, Dict, List, Optional
import requests

from mcp.server.fastmcp import FastMCP

DEFAULT_X64DBG_SERVER = "http://127.0.0.1:8888/"

# Timeout configurations for different operation types
TIMEOUT_FAST = 5
TIMEOUT_NORMAL = 30
TIMEOUT_DEBUG = 120
TIMEOUT_RUN = 15


def _normalize_server_url(url: str) -> str:
    normalized = url.strip()
    if not normalized:
        return DEFAULT_X64DBG_SERVER
    if not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _resolve_server_url() -> str:
    env_url = os.getenv("X64DBG_URL")
    if env_url and env_url.startswith("http"):
        return _normalize_server_url(env_url)
    return DEFAULT_X64DBG_SERVER


x64dbg_server_url = _resolve_server_url()

mcp = FastMCP("x64dbg-mcp")


class DebuggerError(Exception):
    """Raised when the HTTP bridge cannot complete a debugger operation."""


def _parse_json_response(endpoint: str, response: requests.Response) -> Any:
    response.encoding = "utf-8"
    response_text = response.text.strip()
    if not response.ok:
        detail = response_text or response.reason or "HTTP request failed"
        raise DebuggerError(
            f"{endpoint} failed with HTTP {response.status_code}: {detail}"
        )
    try:
        return response.json()
    except ValueError as exc:
        detail = response_text or "<empty body>"
        raise DebuggerError(f"{endpoint} returned invalid JSON: {detail}") from exc


def safe_get(
    endpoint: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = TIMEOUT_NORMAL,
) -> Any:
    if params is None:
        params = {}
    url = f"{x64dbg_server_url}{endpoint}"
    try:
        response = requests.get(url, params=params, timeout=timeout)
    except requests.RequestException as exc:
        raise DebuggerError(f"{endpoint} request failed: {exc}") from exc
    return _parse_json_response(endpoint, response)


def safe_post(
    endpoint: str, data: Dict[str, str] | str, timeout: int = TIMEOUT_NORMAL
) -> Any:
    url = f"{x64dbg_server_url}{endpoint}"
    try:
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=timeout)
    except requests.RequestException as exc:
        raise DebuggerError(f"{endpoint} request failed: {exc}") from exc
    return _parse_json_response(endpoint, response)


def _message_from_result(endpoint: str, result: Any, default: str) -> str:
    payload = _require_json_object(endpoint, result)
    message = payload.get("message")
    if isinstance(message, str) and message:
        return message
    error = payload.get("error")
    if isinstance(error, str) and error:
        return error
    return default


def _require_json_object(endpoint: str, result: Any) -> Dict[str, Any]:
    if isinstance(result, dict):
        return result
    raise DebuggerError(
        f"{endpoint} returned unsupported response type: {type(result).__name__}"
    )


def _require_json_list(endpoint: str, result: Any) -> List[Any]:
    if isinstance(result, list):
        return result
    raise DebuggerError(
        f"{endpoint} returned unsupported response type: {type(result).__name__}"
    )


def _string_field_from_result(endpoint: str, result: Any, field: str) -> str:
    payload = _require_json_object(endpoint, result)
    value = payload.get(field)
    if isinstance(value, str):
        return value
    raise DebuggerError(f"{endpoint} missing string field '{field}': {payload}")


def _bool_field_from_result(endpoint: str, result: Any, field: str) -> bool:
    payload = _require_json_object(endpoint, result)
    value = payload.get(field)
    if isinstance(value, bool):
        return value
    raise DebuggerError(f"{endpoint} missing boolean field '{field}': {payload}")


def _object_get(
    endpoint: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = TIMEOUT_NORMAL,
) -> Dict[str, Any]:
    return _require_json_object(
        endpoint, safe_get(endpoint, params=params, timeout=timeout)
    )


def _list_get(
    endpoint: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = TIMEOUT_NORMAL,
) -> List[Any]:
    return _require_json_list(
        endpoint, safe_get(endpoint, params=params, timeout=timeout)
    )


def _object_post(
    endpoint: str, data: Dict[str, str] | str, timeout: int = TIMEOUT_NORMAL
) -> Dict[str, Any]:
    return _require_json_object(
        endpoint, safe_post(endpoint, data=data, timeout=timeout)
    )


def _string_get(
    endpoint: str,
    field: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = TIMEOUT_NORMAL,
) -> str:
    return _string_field_from_result(
        endpoint, safe_get(endpoint, params=params, timeout=timeout), field
    )


def _bool_get(
    endpoint: str,
    field: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = TIMEOUT_NORMAL,
) -> bool:
    return _bool_field_from_result(
        endpoint, safe_get(endpoint, params=params, timeout=timeout), field
    )


def _message_get(
    endpoint: str,
    default: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = TIMEOUT_NORMAL,
) -> str:
    return _message_from_result(
        endpoint, safe_get(endpoint, params=params, timeout=timeout), default
    )


def _try_parse_int(value: str) -> int | None:
    try:
        return int(value, 0)
    except Exception:
        return None


def _format_memory_read_result(addr: str, size: str, raw_hex: str) -> Dict[str, Any]:
    normalized = "".join(raw_hex.split()).lower()
    if len(normalized) % 2 != 0:
        return {
            "address": addr,
            "requestedSize": size,
            "bytesRead": None,
            "hex": raw_hex,
            "warning": "Memory read returned an odd-length hex string",
        }

    byte_values = [normalized[i : i + 2] for i in range(0, len(normalized), 2)]
    base_addr = _try_parse_int(addr)
    bytes_read = len(byte_values)
    rows: List[Dict[str, Any]] = []

    for row_offset in range(0, bytes_read, 16):
        row_bytes = byte_values[row_offset : row_offset + 16]
        dwords_le = []
        for dword_offset in range(0, len(row_bytes), 4):
            dword_bytes = row_bytes[dword_offset : dword_offset + 4]
            if len(dword_bytes) == 4:
                dwords_le.append("0x" + "".join(reversed(dword_bytes)).upper())

        ascii_preview = "".join(
            chr(int(byte, 16)) if 32 <= int(byte, 16) <= 126 else "."
            for byte in row_bytes
        )

        row: Dict[str, Any] = {
            "offset": f"0x{row_offset:X}",
            "hex": " ".join(row_bytes),
            "dwordsLE": dwords_le,
            "ascii": ascii_preview,
        }
        if base_addr is not None:
            row["address"] = f"0x{base_addr + row_offset:X}"
        rows.append(row)

    return {
        "address": addr,
        "requestedSize": size,
        "bytesRead": f"0x{bytes_read:X}",
        "hex": normalized,
        "rows": rows,
    }


# =============================================================================
# UNIFIED COMMAND EXECUTION
# =============================================================================


@mcp.tool(name="exec.command")
def ExecCommand(cmd: str, offset: int = 0, limit: int = 100) -> dict:
    """
    Execute a command in x64dbg and return its output

    Parameters:
        cmd: Command to execute
        offset: Pagination offset for reference view results (default: 0)
        limit: Maximum number of reference view rows to return (default: 100, max: 5000)

    Returns:
        Dictionary with:
        - success: Whether the command executed successfully
        - refView: References tab data populated by the command (if any), with:
          - rowCount: Total number of rows in the references view
          - rows: List of rows (paginated), where each row is a list of cell strings
                  (typically [address, disassembly] or [address, disassembly, string_address, string])
    """
    return _object_get(
        "cmd",
        params={"command": cmd, "offset": str(offset), "limit": str(limit)},
        timeout=TIMEOUT_NORMAL,
    )


# =============================================================================
# DEBUGGING STATUS
# =============================================================================


@mcp.tool(name="debug.running")
def IsDebugActive() -> bool:
    """
    Check if debugger is active (running)

    Returns:
        True if running, False otherwise
    """
    status = _get_status_data()
    return isinstance(status, dict) and status.get("running") is True


@mcp.tool(name="debug.attached")
def IsDebugging() -> bool:
    """
    Check if x64dbg is debugging a process

    Returns:
        True if debugging, False otherwise
    """
    status = _get_status_data()
    return isinstance(status, dict) and status.get("debugging") is True


def _detect_architecture_from_dump(register_dump: Dict[str, Any]) -> str:
    if not isinstance(register_dump, dict):
        return "unknown"
    if any(
        name in register_dump
        for name in ("r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
    ):
        return "x64"
    return "x86"


def _summarize_registers(register_dump: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(register_dump, dict):
        return {}

    keys = ["cip", "csp", "cbp", "cax", "cbx", "ccx", "cdx", "csi", "cdi"]
    if _detect_architecture_from_dump(register_dump) == "x64":
        keys.extend(["r8", "r9", "r10", "r11"])

    summary = {key: register_dump[key] for key in keys if key in register_dump}
    if "flags" in register_dump:
        summary["flags"] = register_dump["flags"]
    return summary


def _get_status_data() -> Dict[str, Any]:
    return _object_get("status", timeout=TIMEOUT_FAST)


def _get_modules_data() -> List[Dict[str, Any]]:
    return [
        module
        for module in _list_get("modules", timeout=TIMEOUT_NORMAL)
        if isinstance(module, dict)
    ]


@mcp.resource("debugger://status")
def DebuggerStatusResource() -> str:
    """Get current debugger status and basic context as a human-readable summary."""
    status = _get_status_data()
    debugging = status.get("debugging", False) is True
    running = status.get("running", False) is True

    lines = [
        "Debugger Status:",
        f"- Debugging Active: {debugging}",
        f"- Process Running: {running}",
    ]

    if not debugging:
        return "\n".join(lines)

    register_dump = GetRegisterDump()
    architecture = status.get("arch") or _detect_architecture_from_dump(register_dump)
    current_ip = status.get("currentIp") or (
        register_dump.get("cip") if isinstance(register_dump, dict) else None
    )
    lines.append(f"- Architecture: {architecture}")
    if current_ip:
        lines.append(f"- Current IP: {current_ip}")

    if isinstance(register_dump, dict):
        last_error = register_dump.get("lastError")
        last_status = register_dump.get("lastStatus")
        if isinstance(last_error, dict):
            lines.append(
                f"- Last Error: {last_error.get('name', 'unknown')} ({last_error.get('code', 'n/a')})"
            )
        if isinstance(last_status, dict):
            lines.append(
                f"- Last Status: {last_status.get('name', 'unknown')} ({last_status.get('code', 'n/a')})"
            )

    return "\n".join(lines)


@mcp.resource("debugger://modules")
def DebuggerModulesResource() -> str:
    """Get loaded modules as a human-readable summary."""
    modules = _get_modules_data()
    if not isinstance(modules, list) or not modules:
        return "No modules loaded or debugger is not attached."

    lines = [f"Loaded Modules ({len(modules)}):", ""]
    for module in modules:
        if not isinstance(module, dict):
            continue
        name = module.get("name", "<unknown>")
        base = module.get("base", "<unknown>")
        size = module.get("size", "<unknown>")
        entry = module.get("entry", "<unknown>")
        path = module.get("path", "")
        lines.append(f"- {name}")
        lines.append(f"  Base: {base}")
        lines.append(f"  Size: {size}")
        lines.append(f"  Entry: {entry}")
        if path:
            lines.append(f"  Path: {path}")
        lines.append("")

    return "\n".join(lines).rstrip()


@mcp.prompt()
def analyze_function() -> str:
    """Prompt scaffold for analyzing the current or selected function."""
    return (
        "先获取 debugger://status 和 analysis.current-location，确认当前架构、RIP/EIP、模块和注释上下文。"
        "如果当前位置在函数内，再查看 disasm.range、label.get、comment.get、xref.list，"
        "必要时配合 symbol.query 和 exec.command 做进一步分析。"
    )


@mcp.prompt()
def trace_execution() -> str:
    """Prompt scaffold for step-tracing or run-control analysis."""
    return (
        "先用 debug.status 确认调试状态，再根据需要选择 debug.pause、debug.run、debug.step-in、debug.step-over、debug.step-out。"
        "分析当前执行位置时优先使用 analysis.current-location、register.dump、stack.peek 和 disasm.range。"
    )


@mcp.prompt()
def find_crypto() -> str:
    """Prompt scaffold for crypto-hunting workflows."""
    return (
        "先获取 debugger://modules 与 debug.status，定位主模块后用 symbol.query、pattern.find、xref.list、string.at。"
        "重点关注常量表、循环、XOR/AES/SHA 相关调用，以及可疑的私有可执行内存页。"
    )


@mcp.tool(name="debug.status")
def GetStatus() -> Dict[str, Any]:
    """
    Get a compact debugger status object using the /status endpoint.

    Returns:
        Dictionary containing architecture, debugging state, running state, and optional current IP.
    """
    return _get_status_data()


@mcp.tool(name="analysis.current-location")
def AnalyzeCurrentLocation() -> Dict[str, Any]:
    """
    Get a compact view of the current debugger location.

    Returns:
        Dictionary with debugger status, a register summary, current instruction,
        and basic module/comment/label context for the current instruction pointer.
    """
    debugging = IsDebugging()
    running = IsDebugActive() if debugging else False
    status = {
        "debugging": debugging,
        "running": running,
    }

    if not debugging:
        return {
            "status": status,
            "error": "No active debug session",
        }

    register_dump = GetRegisterDump()
    architecture = _detect_architecture_from_dump(register_dump)
    current_ip = register_dump.get("cip") if isinstance(register_dump, dict) else None

    result: Dict[str, Any] = {
        "status": {
            **status,
            "architecture": architecture,
        },
        "registers": _summarize_registers(register_dump),
        "location": current_ip,
    }

    if not current_ip:
        result["error"] = "Current instruction pointer is unavailable"
        return result

    instruction = DisasmGetInstructionRange(current_ip, 1)
    if isinstance(instruction, list) and instruction:
        result["instruction"] = instruction[0]

    module_info = MemoryBase(current_ip)
    if isinstance(module_info, dict):
        result["module"] = module_info

    label_info = LabelGet(current_ip)
    if isinstance(label_info, dict) and label_info.get("found"):
        result["label"] = label_info.get("label", "")

    comment_info = CommentGet(current_ip)
    if isinstance(comment_info, dict) and comment_info.get("found"):
        result["comment"] = comment_info.get("comment", "")

    return result


# =============================================================================
# REGISTER API
# =============================================================================


@mcp.tool(name="register.get")
def RegisterGet(register: str) -> str:
    """
    Get register value using Script API

    Parameters:
        register: Register name (e.g. "eax", "rax", "rip")

    Returns:
        Register value in hex format
    """
    return _string_get(
        "register/get", "value", {"name": register}, timeout=TIMEOUT_FAST
    )


@mcp.tool(name="register.set")
def RegisterSet(register: str, value: str) -> str:
    """
    Set register value using Script API

    Parameters:
        register: Register name (e.g. "eax", "rax", "rip")
        value: Value to set (in hex format, e.g. "0x1000")

    Returns:
        Status message
    """
    return _message_get(
        "register/set",
        "Register set request completed",
        {"name": register, "value": value},
        timeout=TIMEOUT_NORMAL,
    )


# =============================================================================
# MEMORY API
# =============================================================================


@mcp.tool(name="memory.read")
def MemoryRead(addr: str, size: str) -> Dict[str, Any]:
    """
    Read memory using enhanced Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        size: Number of bytes to read (decimal or 0x-prefixed hex)

    Returns:
        Dictionary containing the raw hex string and row-based formatted output
    """
    result = _object_get(
        "memory/read", {"addr": addr, "size": size}, timeout=TIMEOUT_NORMAL
    )
    raw_hex = result.get("hex")
    if not isinstance(raw_hex, str):
        raise DebuggerError(f"memory/read missing string field 'hex': {result}")
    formatted = _format_memory_read_result(
        result.get("address", addr),
        result.get("requestedSize", size),
        raw_hex,
    )
    if isinstance(result.get("bytesRead"), str):
        formatted["bytesRead"] = result["bytesRead"]
    return formatted


@mcp.tool(name="memory.write")
def MemoryWrite(addr: str, data: str) -> Dict[str, Any]:
    """
    Write memory using enhanced Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        data: Hexadecimal string representing the data to write

    Returns:
        Status message
    """
    return _object_get(
        "memory/write", {"addr": addr, "data": data}, timeout=TIMEOUT_NORMAL
    )


@mcp.tool(name="memory.is-valid")
def MemoryIsValidPtr(addr: str) -> bool:
    """
    Check if memory address is valid

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        True if valid, False otherwise
    """
    return _bool_get("memory/is-valid", "valid", {"addr": addr}, timeout=TIMEOUT_FAST)


@mcp.tool(name="memory.protect")
def MemoryGetProtect(addr: str) -> str:
    """
    Get memory protection flags

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        Protection flags in hex format
    """
    return _string_get(
        "memory/protect", "protect", {"addr": addr}, timeout=TIMEOUT_FAST
    )


# =============================================================================
# DEBUG API
# =============================================================================


@mcp.tool(name="debug.run")
def DebugRun() -> str:
    """
    Resume execution of the debugged process using Script API

    Returns:
        Status message
    """
    state = _get_status_data()
    if isinstance(state, dict) and state.get("running") is True:
        return "Debugger already running"
    return _message_get("debug/run", "Debug run request completed", timeout=TIMEOUT_RUN)


@mcp.tool(name="debug.pause")
def DebugPause() -> str:
    """
    Pause execution of the debugged process using Script API

    Returns:
        Status message
    """
    return _message_get(
        "debug/pause", "Debug pause request completed", timeout=TIMEOUT_DEBUG
    )


@mcp.tool(name="debug.stop")
def DebugStop() -> str:
    """
    Stop debugging using Script API

    Returns:
        Status message
    """
    return _message_get(
        "debug/stop", "Debug stop request completed", timeout=TIMEOUT_DEBUG
    )


@mcp.tool(name="debug.step-in")
def DebugStepIn() -> str:
    """
    Step into the next instruction using Script API

    Returns:
        Status message
    """
    return _message_get(
        "debug/step-in", "Step in request completed", timeout=TIMEOUT_DEBUG
    )


@mcp.tool(name="debug.step-over")
def DebugStepOver() -> str:
    """
    Step over the next instruction using Script API

    Returns:
        Status message
    """
    return _message_get(
        "debug/step-over", "Step over request completed", timeout=TIMEOUT_DEBUG
    )


@mcp.tool(name="debug.step-out")
def DebugStepOut() -> str:
    """
    Step out of the current function using Script API

    Returns:
        Status message
    """
    return _message_get(
        "debug/step-out", "Step out request completed", timeout=TIMEOUT_DEBUG
    )


@mcp.tool(name="breakpoint.set")
def DebugSetBreakpoint(addr: str) -> str:
    """
    Set breakpoint at address using Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        Status message
    """
    return _message_get(
        "breakpoint/set",
        "Breakpoint set request completed",
        {"addr": addr},
        timeout=TIMEOUT_NORMAL,
    )


@mcp.tool(name="breakpoint.delete")
def DebugDeleteBreakpoint(addr: str) -> str:
    """
    Delete breakpoint at address using Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        Status message
    """
    return _message_get(
        "breakpoint/delete",
        "Breakpoint delete request completed",
        {"addr": addr},
        timeout=TIMEOUT_NORMAL,
    )


# =============================================================================
# ASSEMBLER API
# =============================================================================


@mcp.tool(name="assembler.assemble")
def AssemblerAssemble(addr: str, instruction: str) -> dict:
    """
    Assemble instruction at address using Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        instruction: Assembly instruction (e.g. "mov eax, 1")

    Returns:
        Dictionary with assembly result
    """
    return _object_get(
        "assembler/assemble",
        {"addr": addr, "instruction": instruction},
        timeout=TIMEOUT_NORMAL,
    )


@mcp.tool(name="assembler.write")
def AssemblerAssembleMem(addr: str, instruction: str) -> str:
    """
    Assemble instruction directly into memory using Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        instruction: Assembly instruction (e.g. "mov eax, 1")

    Returns:
        Status message
    """
    return _message_get(
        "assembler/write",
        "Assembler write request completed",
        {"addr": addr, "instruction": instruction},
        timeout=TIMEOUT_NORMAL,
    )


# =============================================================================
# STACK API
# =============================================================================


@mcp.tool(name="stack.pop")
def StackPop() -> str:
    """
    Pop value from stack using Script API

    Returns:
        Popped value in hex format
    """
    return _string_get("stack/pop", "value", timeout=TIMEOUT_NORMAL)


@mcp.tool(name="stack.push")
def StackPush(value: str) -> str:
    """
    Push value to stack using Script API

    Parameters:
        value: Value to push (in hex format, e.g. "0x1000")

    Returns:
        Previous top value in hex format
    """
    return _string_get(
        "stack/push", "previousTop", {"value": value}, timeout=TIMEOUT_NORMAL
    )


@mcp.tool(name="stack.peek")
def StackPeek(offset: str = "0") -> str:
    """
    Peek at stack value using Script API

    Parameters:
        offset: Stack offset (default: "0")

    Returns:
        Stack value in hex format
    """
    return _string_get(
        "stack/peek", "value", {"offset": offset}, timeout=TIMEOUT_NORMAL
    )


# =============================================================================
# FLAG API
# =============================================================================


@mcp.tool(name="flag.get")
def FlagGet(flag: str) -> bool:
    """
    Get CPU flag value using Script API

    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)

    Returns:
        Flag value (True/False)
    """
    return _bool_get("flag/get", "value", {"flag": flag}, timeout=TIMEOUT_FAST)


@mcp.tool(name="flag.set")
def FlagSet(flag: str, value: bool) -> str:
    """
    Set CPU flag value using Script API

    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)
        value: Flag value (True/False)

    Returns:
        Status message
    """
    return _message_get(
        "flag/set",
        "Flag set request completed",
        {"flag": flag, "value": "true" if value else "false"},
        timeout=TIMEOUT_NORMAL,
    )


# =============================================================================
# PATTERN API
# =============================================================================


@mcp.tool(name="pattern.find")
def PatternFindMem(start: str, size: str, pattern: str) -> str:
    """
    Find pattern in memory using Script API

    Parameters:
        start: Start address (in hex format, e.g. "0x1000")
        size: Size to search IN DECIMAL
        pattern: Pattern to find (e.g. "48 8B 05 ?? ?? ?? ??")

    Returns:
        Found address in hex format or error message
    """
    return _string_get(
        "pattern/find",
        "address",
        {"start": start, "size": size, "pattern": pattern},
        timeout=TIMEOUT_NORMAL,
    )


# =============================================================================
# MISC API
# =============================================================================


@mcp.tool(name="expression.parse")
def MiscParseExpression(expression: str) -> str:
    """
    Parse expression using Script API

    Parameters:
        expression: Expression to parse (e.g. "[esp+8]")

    Returns:
        Parsed value in hex format
    """
    return _string_get(
        "expression/parse", "value", {"expression": expression}, timeout=TIMEOUT_NORMAL
    )


@mcp.tool(name="module.proc-address")
def MiscRemoteGetProcAddress(module: str, api: str) -> str:
    """
    Get remote procedure address using Script API

    Parameters:
        module: Module name (e.g. "kernel32.dll")
        api: API name (e.g. "GetProcAddress")

    Returns:
        Function address in hex format
    """
    return _string_get(
        "module/proc-address",
        "address",
        {"module": module, "api": api},
        timeout=TIMEOUT_NORMAL,
    )


# =============================================================================
# DISASSEMBLY API
# =============================================================================


@mcp.tool(name="disasm.range")
def DisasmGetInstructionRange(addr: str, count: int = 1) -> list:
    """
    Get disassembly of multiple instructions starting at the specified address

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        count: Number of instructions to disassemble (default: 1, max: 100)

    Returns:
        List of dictionaries containing instruction details
    """
    result = _list_get(
        "disasm/range", {"addr": addr, "count": str(count)}, timeout=TIMEOUT_NORMAL
    )
    if result:
        return result
    # FastMCP can choke on empty list tool results, so return an explicit miss item.
    return [{"address": addr, "instruction": "", "size": 0, "found": False}]


@mcp.tool(name="disasm.step-into")
def StepInWithDisasm() -> dict:
    """
    Step into the next instruction and return both step result and current instruction disassembly

    Returns:
        Dictionary containing step result and current instruction info
    """
    return _object_get("disasm/step-into", timeout=TIMEOUT_DEBUG)


@mcp.tool(name="module.list")
def GetModuleList() -> list:
    """
    Get list of loaded modules

    Returns:
        List of module information (name, base address, size, etc.)
    """
    return _list_get("modules", timeout=TIMEOUT_NORMAL)


@mcp.tool(name="symbol.query")
def QuerySymbols(module: str, offset: int = 0, limit: int = 5000) -> dict:
    """
    Enumerate symbols for a specific module. Use GetModuleList first to discover module names.
    Returns imports, exports, and user-defined function symbols for the given module.

    Args:
        module: Module name to query symbols for (e.g. "kernel32.dll", "ntdll.dll"). Required.
        offset: Pagination offset - number of symbols to skip (default: 0)
        limit: Maximum number of symbols to return per page (default: 5000, max: 50000)

    Returns:
        Dictionary with:
        - total: Total number of symbols in the module
        - module: The module name queried
        - offset: Current offset
        - limit: Current limit
        - symbols: List of symbol objects with rva, name, manual, type fields
    """
    params = {
        "module": module,
        "offset": str(offset),
        "limit": str(limit),
    }

    return _object_get("symbols", params)


@mcp.tool(name="thread.list")
def GetThreadList() -> dict:
    """
    Get list of all threads in the debugged process with detailed information.

    Returns:
        Dictionary with:
        - count: Number of threads
        - currentThread: Index of the currently focused thread
        - threads: List of thread objects with threadNumber, threadId, threadName,
          startAddress, localBase, cip, suspendCount, priority, waitReason,
          lastError, cycles
    """
    return _object_get("threads")


@mcp.tool(name="thread.teb")
def GetTebAddress(tid: str) -> dict:
    """
    Get the Thread Environment Block (TEB) address for a specific thread.
    Use GetThreadList first to discover thread IDs.

    Args:
        tid: Thread ID (decimal integer string, e.g. "1234")

    Returns:
        Dictionary with tid and tebAddress fields
    """
    return _object_get("thread/teb", {"tid": tid})


@mcp.tool(name="module.by-address")
def MemoryBase(addr: str) -> dict:
    """
    Find the base address and size of a module containing the given address

    Parameters:
        addr: Memory address (in hex format, e.g. "0x7FF12345")

    Returns:
        Dictionary containing base_address and size of the module
    """
    return _object_get("module/by-address", {"addr": addr})


@mcp.tool(name="memory.protect.set")
def SetPageRights(addr: str, rights: str) -> bool:
    """
    Set memory page protection rights at a given address

    Args:
        addr: Virtual address (hex string, e.g. "0x401000")
        rights: Rights string (e.g. "rwx", "rx", "rw", "ERW", "ER", "RW")

    Returns:
        True if successful, False otherwise
    """
    params = {"addr": addr, "rights": rights}

    return _bool_field_from_result(
        "memory/protect/set", _object_post("memory/protect/set", params), "success"
    )


# =============================================================================
# STRING API
# =============================================================================


@mcp.tool(name="string.at")
def StringGetAt(addr: str) -> dict:
    """
    Retrieve the string at a given address in the debugged process.
    Uses x64dbg's internal string detection (same as the disassembly view).

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a string was detected at that address
        - string: The string content (empty if not found)
    """
    return _object_get("string/at", {"addr": addr})


# =============================================================================
# XREF (CROSS-REFERENCE) API
# =============================================================================


@mcp.tool(name="xref.list")
def XrefGet(addr: str) -> dict:
    """
    Get all cross-references (xrefs) TO the specified address.
    Returns the list of addresses that reference the target address,
    along with the type of each reference (data, jmp, call).

    Note: Results depend on x64dbg's analysis database. Run analysis
    first for comprehensive results.

    Parameters:
        addr: Target address to find references to (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried target address
        - refcount: Number of cross-references found
        - references: List of reference objects, each with:
          - addr: Address of the referrer (the instruction that references the target)
          - type: Reference type ("data", "jmp", "call", or "none")
          - string: Optional string context at the referrer address
    """
    return _object_get("xref/list", {"addr": addr})


@mcp.tool(name="xref.count")
def XrefCount(addr: str) -> dict:
    """
    Get the count of cross-references to the specified address.
    This is a lightweight check that doesn't fetch the full reference list.

    Parameters:
        addr: Target address to count references for (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - count: Number of cross-references
    """
    return _object_get("xref/count", {"addr": addr})


# =============================================================================
# MEMORY MAP API
# =============================================================================


@mcp.tool(name="memory.map")
def GetMemoryMap() -> dict:
    """
    Get the full virtual memory map of the debugged process.
    Returns all memory pages with their base address, size, protection, type, and info.

    Returns:
        Dictionary with:
        - count: Number of memory pages
        - pages: List of page objects with base, size, protect (ERW/ER-/-RW/-R-/E--/---),
          type (IMG/MAP/PRV), and info (module name or description)
    """
    return _object_get("memory/map")


# =============================================================================
# REMOTE MEMORY ALLOC/FREE API
# =============================================================================


@mcp.tool(name="memory.alloc")
def MemoryRemoteAlloc(size: str, addr: str = "0") -> dict:
    """
    Allocate memory in the debuggee's address space.
    Useful for code injection, shellcode testing, or creating data buffers.

    Parameters:
        size: Size in bytes to allocate (hex format, e.g. "0x1000")
        addr: Preferred base address (hex format, default "0" for any address)

    Returns:
        Dictionary with:
        - address: The allocated memory address
        - size: The requested size
    """
    return _object_get("memory/alloc", {"addr": addr, "size": size})


@mcp.tool(name="memory.free")
def MemoryRemoteFree(addr: str) -> dict:
    """
    Free memory previously allocated in the debuggee's address space via MemoryRemoteAlloc.

    Parameters:
        addr: Address of the memory to free (hex format, e.g. "0x1000")

    Returns:
        Dictionary with success status
    """
    return _object_get("memory/free", {"addr": addr})


# =============================================================================
# BRANCH DESTINATION API
# =============================================================================


@mcp.tool(name="branch.destination")
def GetBranchDestination(addr: str) -> dict:
    """
    Get the destination address of a branch instruction (jmp, call, jcc, etc.).
    Resolves where the branch at the given address would jump/call to.

    Parameters:
        addr: Address of the branch instruction (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried instruction address
        - destination: The resolved target address
        - resolved: Whether the destination was successfully resolved
    """
    return _object_get("branch/destination", {"addr": addr})


# =============================================================================
# CALL STACK API
# =============================================================================


@mcp.tool(name="callstack.get")
def GetCallStack() -> dict:
    """
    Get the current call stack of the debugged thread.
    Returns the full stack trace with addresses, return addresses, and comments.

    Returns:
        Dictionary with:
        - total: Number of stack frames
        - entries: List of call stack entries, each with:
          - addr: Current address in the frame
          - from: Return address (caller)
          - to: Called address (callee)
          - comment: Auto-generated comment (function name, etc.)
    """
    return _object_get("callstack")


# =============================================================================
# BREAKPOINT LIST API
# =============================================================================


@mcp.tool(name="breakpoint.list")
def GetBreakpointList(type: str = "all") -> dict:
    """
    Get list of all breakpoints currently set in the debugger.

    Parameters:
        type: Breakpoint type filter - "all" (default), "normal", "hardware", "memory", "dll", "exception"

    Returns:
        Dictionary with:
        - count: Number of breakpoints
        - breakpoints: List of breakpoint objects with type, addr, enabled, singleshoot,
          active, name, module, hitCount, fastResume, silent, breakCondition, logText, commandText
    """
    return _object_get("breakpoint/list", {"type": type})


# =============================================================================
# LABEL API
# =============================================================================


@mcp.tool(name="label.set")
def LabelSet(addr: str, text: str) -> dict:
    """
    Set a label at the specified address in x64dbg.
    Labels appear in the disassembly view and are useful for marking important addresses.

    Parameters:
        addr: Address to set the label at (hex format, e.g. "0x1400010a0")
        text: Label text (e.g. "main_decrypt_loop")

    Returns:
        Dictionary with success status, address, and label text
    """
    return _object_get("label/set", {"addr": addr, "text": text})


@mcp.tool(name="label.get")
def LabelGet(addr: str) -> dict:
    """
    Get the label at the specified address.

    Parameters:
        addr: Address to query (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a label exists at that address
        - label: The label text (empty if not found)
    """
    return _object_get("label/get", {"addr": addr})


@mcp.tool(name="label.list")
def LabelList() -> dict:
    """
    Get all labels defined in the current debugging session.

    Returns:
        Dictionary with:
        - count: Number of labels
        - labels: List of label objects with module, rva, text, and manual fields
    """
    return _object_get("label/list")


# =============================================================================
# COMMENT API
# =============================================================================


@mcp.tool(name="comment.set")
def CommentSet(addr: str, text: str) -> dict:
    """
    Set a comment at the specified address in x64dbg.
    Comments appear in the disassembly view next to the instruction.

    Parameters:
        addr: Address to set the comment at (hex format, e.g. "0x1400010a0")
        text: Comment text

    Returns:
        Dictionary with success status and address
    """
    return _object_get("comment/set", {"addr": addr, "text": text})


@mcp.tool(name="comment.get")
def CommentGet(addr: str) -> dict:
    """
    Get the comment at the specified address.

    Parameters:
        addr: Address to query (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a comment exists
        - comment: The comment text
    """
    return _object_get("comment/get", {"addr": addr})


# =============================================================================
# REGISTER DUMP API
# =============================================================================


@mcp.tool(name="register.dump")
def GetRegisterDump() -> dict:
    """
    Get a complete dump of all CPU registers in one call.
    Returns general purpose registers, segment registers, debug registers,
    flags, and last error/status information.

    Much more efficient than reading registers individually.

    Returns:
        Dictionary with all register values (cax/ccx/cdx/cbx/csp/cbp/csi/cdi,
        r8-r15 on x64, cip, eflags, segment regs, debug regs, flags object,
        lastError, lastStatus)
    """
    return _object_get("registers")


# =============================================================================
# HARDWARE BREAKPOINT API
# =============================================================================


@mcp.tool(name="breakpoint.hardware.set")
def SetHardwareBreakpoint(addr: str, type: str = "execute") -> dict:
    """
    Set a hardware breakpoint at the specified address.
    Hardware breakpoints use CPU debug registers (limited to 4 simultaneous).

    Parameters:
        addr: Address to set the breakpoint at (hex format, e.g. "0x1400010a0")
        type: Breakpoint type - "execute" (default), "access" (read/write), or "write" (write only)

    Returns:
        Dictionary with success status and address
    """
    return _object_get("breakpoint/hardware/set", {"addr": addr, "type": type})


@mcp.tool(name="breakpoint.hardware.delete")
def DeleteHardwareBreakpoint(addr: str) -> dict:
    """
    Delete a hardware breakpoint at the specified address.

    Parameters:
        addr: Address of the hardware breakpoint to delete (hex format)

    Returns:
        Dictionary with success status and address
    """
    return _object_get("breakpoint/hardware/delete", {"addr": addr})


# =============================================================================
# TCP CONNECTIONS API
# =============================================================================


@mcp.tool(name="network.tcp")
def EnumTcpConnections() -> dict:
    """
    Enumerate all TCP connections of the debugged process.
    Useful for analyzing network activity, identifying C2 connections, etc.

    Returns:
        Dictionary with:
        - count: Number of connections
        - connections: List of connection objects with remoteAddress, remotePort,
          localAddress, localPort, and state
    """
    return _object_get("network/tcp")


# =============================================================================
# PATCH API
# =============================================================================


@mcp.tool(name="patch.list")
def GetPatchList() -> dict:
    """
    Enumerate all memory patches applied in the current debugging session.
    Shows original and patched byte values for each patched address.

    Returns:
        Dictionary with:
        - count: Number of patches
        - patches: List of patch objects with module, address, oldByte, newByte
    """
    return _object_get("patch/list")


@mcp.tool(name="patch.get")
def GetPatchAt(addr: str) -> dict:
    """
    Check if a specific address has been patched and get patch details.

    Parameters:
        addr: Address to check (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - patched: Whether the address is patched
        - module: Module name (if patched)
        - oldByte: Original byte value (if patched)
        - newByte: Patched byte value (if patched)
    """
    return _object_get("patch/get", {"addr": addr})


# =============================================================================
# HANDLE ENUMERATION API
# =============================================================================


@mcp.tool(name="handle.list")
def EnumHandles() -> dict:
    """
    Enumerate all open handles in the debugged process.
    Returns handle values, types, access rights, names, and type names.
    Useful for analyzing file handles, registry keys, mutexes, events, etc.

    Returns:
        Dictionary with:
        - count: Number of handles
        - handles: List of handle objects with handle (hex), typeNumber,
          grantedAccess (hex), name, and typeName
    """
    return _object_get("handles")


if __name__ == "__main__":
    mcp.run()
