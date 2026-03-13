rule Supply_Chain_Campaign_Indicators {
    meta:
        description = "Detects known supply chain attack obfuscation markers and campaign patterns"
        author = "Guardian Project"
        date = "2026-02-20"
        severity = "critical"
        tlp = "WHITE"
        mitre_attack = "T1195.001,T1059.007,T1036.005,T1027.013,T1102.002,T1573.001"

    strings:
        // Campaign identifiers
        $campaign_id1 = "8-404-2" ascii wide
        $campaign_id2 = "A8-404-2" ascii wide
        $namespace = "@pinetech" ascii wide

        // Obfuscation decoder function names
        $decoder1 = "_$_1e42" ascii
        $decoder2 = "_$af163278" ascii
        $decoder3 = "_$_ccfc" ascii
        $cipher_fn = "sfL(" ascii

        // Obfuscation cipher seeds
        $seed1 = "2857687" ascii
        $seed2 = "2667686" ascii
        $seed3 = "1812138" ascii

        // C2 delimiter (raw bytes for '?.?')
        $delimiter = { 27 3f 2e 3f 27 }

        // Campaign marker code patterns
        $global_marker1 = "global['!']" ascii
        $global_marker2 = "global[\"!\"]" ascii
        $global_v = "global._V" ascii

        // Attacker commit message patterns
        $commit_msg = "Factory push due to factory error" ascii nocase

        // C2 hostname identifier
        $c2_hostname = "EV-4A6OE6M0E2D" ascii

    condition:
        any of them
}
