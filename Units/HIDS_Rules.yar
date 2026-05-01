rule HIDS_Test_String
{
    meta:
        description = "Test rule for checking that YARA works"

    strings:
        $test = "HIDS_YARA_TEST" ascii wide

    condition:
        $test
}


rule Suspicious_Script_Keywords
{
    meta:
        description = "Detects suspicious script-related keywords"

    strings:
        $powershell = "powershell" ascii wide nocase
        $iex = "invoke-expression" ascii wide nocase
        $base64 = "frombase64string" ascii wide nocase
        $download = "downloadstring" ascii wide nocase
        $cmd = "cmd.exe" ascii wide nocase

    condition:
        2 of them
}