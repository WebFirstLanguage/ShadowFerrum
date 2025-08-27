# PowerShell script to test the API endpoints

Write-Host "Testing ShadowFerrum API..." -ForegroundColor Green
Write-Host ""

# Test health check
Write-Host "1. Testing health check endpoint..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/ping" -Method Get
Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host "   Response: $($response.Content)" -ForegroundColor Gray
Write-Host ""

# Create a directory
Write-Host "2. Creating directory /testdir..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/testdir" -Method Post
Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host ""

# Upload a file
Write-Host "3. Uploading file /testdir/hello.txt..." -ForegroundColor Yellow
$content = [System.Text.Encoding]::UTF8.GetBytes("Hello from ShadowFerrum!")
$response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/testdir/hello.txt" -Method Put -Body $content
Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host ""

# Read the file
Write-Host "4. Reading file /testdir/hello.txt..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/testdir/hello.txt" -Method Get
Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host "   Content: $($response.Content)" -ForegroundColor Gray
Write-Host ""

# Get file metadata
Write-Host "5. Getting file metadata /testdir/hello.txt..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/testdir/hello.txt" -Method Head
Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host "   Content-Length: $($response.Headers['Content-Length'])" -ForegroundColor Gray
Write-Host "   X-File-Type: $($response.Headers['X-File-Type'])" -ForegroundColor Gray
Write-Host ""

# List directory
Write-Host "6. Listing directory /testdir..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/testdir" -Method Get
Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host "   Entries: $($response.Content)" -ForegroundColor Gray
Write-Host ""

# Delete the file
Write-Host "7. Deleting file /testdir/hello.txt..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/testdir/hello.txt" -Method Delete
Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host ""

# Delete the directory
Write-Host "8. Deleting directory /testdir..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://127.0.0.1:3000/testdir" -Method Delete
Write-Host "   Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host ""

Write-Host "All tests completed successfully!" -ForegroundColor Green