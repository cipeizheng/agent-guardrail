rule ag_prompt_instruction_override
{
    strings:
        $ignore_all = "ignore all previous instructions" ascii nocase
        $ignore_previous = "ignore previous instructions" ascii nocase
        $disregard = "disregard all previous instructions" ascii nocase
        $system_prompt = "reveal the system prompt" ascii nocase
    condition:
        any of them
}

rule ag_sql_injection
{
    strings:
        $union_select = "union select" ascii nocase
        $tautology_single = "' or '1'='1" ascii nocase
        $tautology_plain = "or 1=1" ascii nocase
        $information_schema = "information_schema" ascii nocase
    condition:
        any of them
}

rule ag_template_injection
{
    strings:
        $jndi = "${jndi:" ascii nocase
        $python_mro = "__class__.__mro__" ascii
        $jinja_probe = "{{7*7}}" ascii
        $erb = "<%=" ascii
    condition:
        any of them
}

rule ag_xss_injection
{
    strings:
        $script = "<script" ascii nocase
        $javascript = "javascript:alert(" ascii nocase
        $event_handler = "onerror=" ascii nocase
    condition:
        any of them
}

rule ag_code_injection
{
    strings:
        $python_import = "__import__(\"os\").system" ascii
        $python_subprocess = "subprocess.Popen(" ascii
        $java_runtime = "Runtime.getRuntime().exec(" ascii
    condition:
        any of them
}
