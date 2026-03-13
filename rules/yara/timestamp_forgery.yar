rule Timestamp_Forgery_Script {
    meta:
        description = "Detects timestamp forgery toolkit scripts used in supply chain attacks"
        author = "Guardian Project"
        date = "2026-02-20"
        severity = "critical"
        tlp = "WHITE"
        mitre_attack = "T1070.006"

    strings:
        // Git commit manipulation
        $git_amend = "git commit --amend" ascii nocase
        $no_verify = "--no-verify" ascii
        $force_push = "git push" ascii
        $force_flag = "-uf" ascii

        // Windows time manipulation
        $time_resync = "w32tm /resync" ascii nocase
        $w32tm = "w32tm" ascii nocase

        // Git log format for date extraction
        $git_log_format = "git log -1 --format" ascii

        // Date variable manipulation
        $set_date = /SET\s+LAST_DATE/i ascii

        // Git environment variable forgery
        $git_committer_date = "GIT_COMMITTER_DATE" ascii
        $git_author_date = "GIT_AUTHOR_DATE" ascii
        $git_committer_name = "GIT_COMMITTER_NAME" ascii
        $git_author_name = "GIT_AUTHOR_NAME" ascii

        // Windows date/time commands used in the toolkit
        $date_cmd = /date\s+\/T/i ascii
        $time_cmd = /time\s+\/T/i ascii

        // Batch file patterns
        $echo_off = "@echo off" ascii nocase
        $for_f = /FOR\s+\/F/i ascii

    condition:
        3 of them
}

rule Git_Identity_Forgery {
    meta:
        description = "Detects scripts that forge git commit identity to impersonate CI/CD bots"
        author = "Guardian Project"
        date = "2026-02-20"
        severity = "critical"
        tlp = "WHITE"
        mitre_attack = "T1036.005"

    strings:
        $committer_name = "GIT_COMMITTER_NAME" ascii
        $author_name = "GIT_AUTHOR_NAME" ascii
        $vercel_bot = "vercel[bot]" ascii
        $dependabot = "dependabot[bot]" ascii
        $renovate_bot = "renovate[bot]" ascii
        $github_actions = "github-actions[bot]" ascii
        $git_commit = "git commit" ascii
        $git_push = "git push" ascii

    condition:
        ($committer_name or $author_name) and
        ($vercel_bot or $dependabot or $renovate_bot or $github_actions) and
        ($git_commit or $git_push)
}
