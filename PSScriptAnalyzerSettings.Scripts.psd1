@{
    # Settings for the developer-facing scripts in scripts/ and samples/. They are run by a
    # human at a console, not imported as a module, so the module settings are relaxed in
    # exactly one place.
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions'

        # These scripts write a progress narrative to the host on purpose, and it must NOT go
        # to the success stream: mint-license.ps1 emits the licence key on stdout so it can be
        # piped or redirected, and New-SampleReport.ps1 emits the report path. Folding the
        # human-readable commentary into those streams would corrupt both.
        'PSAvoidUsingWriteHost'
    )
}
