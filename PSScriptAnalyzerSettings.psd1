@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # PSUseShouldProcessForStateChangingFunctions fires on the New-* factories in
        # Private/ (a signal, a trip, a decoy record), which build in-memory objects and
        # touch nothing outside the process.
        #
        # The rule exists to catch functions that change a system without asking. The four
        # functions in this module that CAN change a tenant -- New-TripwireDecoy,
        # Remove-TripwireDecoy, Invoke-TripwireContainment and Enable-TripwirePro -- all
        # implement SupportsShouldProcess, and tests/Safety.Tests.ps1 fails the build if a
        # write reaches Graph outside the audited allowlist in Invoke-TripwireGraphWrite.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
