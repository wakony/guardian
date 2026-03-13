rule Config_File_Injection {
    meta:
        description = "Generic detection for JavaScript config file payload injection"
        author = "Guardian Project"
        date = "2026-02-20"
        severity = "high"
        tlp = "WHITE"
        mitre_attack = "T1195.001,T1059.007,T1027.013"

    strings:
        // Suspicious imports that should NOT appear in build config files
        $createRequire = "createRequire" ascii
        $child_process = "child_process" ascii

        // Code execution patterns
        $eval_call = /eval\s*\(/ ascii
        $function_ctor = /new\s+Function\s*\(/ ascii
        $function_ctor2 = /Function\s*\(/ ascii
        $fromCharCode = "String.fromCharCode" ascii

        // Trailing whitespace payload (100+ consecutive spaces)
        $long_spaces = /\x20{100,}/

        // Blockchain API references (C2 technique indicators)
        $trongrid = "trongrid.io" ascii
        $aptoslabs = "aptoslabs.com" ascii
        $bsc_dataseed = "bsc-dataseed" ascii
        $bsc_rpc = "bsc-rpc.publicnode" ascii
        $eth_rpc_method = "eth_getTransactionByHash" ascii

        // Campaign marker patterns
        $global_marker = /global\[['"][^'"]{1,20}['"]\]\s*=/ ascii
        $global_underscore = /global\._[A-Za-z]/ ascii

        // Hidden process execution
        $hidden_window1 = "windowsHide:true" ascii
        $hidden_window2 = "windowsHide: true" ascii
        $detached1 = "detached:true" ascii
        $detached2 = "detached: true" ascii

        // Process environment access (credential theft)
        $process_env = "process.env" ascii
        $spawn_node = /spawn\s*\(\s*['"]node['"]/ ascii

    condition:
        filesize < 100KB and
        (
            ($createRequire and ($child_process or $eval_call or $function_ctor or $function_ctor2)) or
            ($long_spaces) or
            ($global_marker and any of ($trongrid, $aptoslabs, $bsc_dataseed, $bsc_rpc, $eth_rpc_method)) or
            (($hidden_window1 or $hidden_window2) and ($detached1 or $detached2)) or
            (4 of them) or
            ($spawn_node and $process_env and ($eval_call or $fromCharCode))
        )
}
