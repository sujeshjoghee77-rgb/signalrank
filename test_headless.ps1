$p = Start-Process -FilePath "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "--headless", "--disable-gpu", "--dump-dom", "file:///C:/Users/sujes/.gemini/antigravity-ide/scratch/signalrank/test_runner.html" -NoNewWindow -PassThru -RedirectStandardOutput "test_output.html"
Start-Sleep -Seconds 2
if (Test-Path "test_output.html") {
    $content = Get-Content "test_output.html" -Raw
    Write-Host "Output length: $($content.Length) bytes"
    Get-Content "test_output.html" | Select-String -Pattern "statPassed|statFailed|ALL .* PASSED|suite-name" | Select-Object -First 20
}
