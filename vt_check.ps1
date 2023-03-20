# Define your VirusTotal API key
$apiKey = "YOUR_API_KEY"

# Define the path to your .txt file containing URLs
$urlListPath = "C:\path\to\your\url_list.txt"

# Read the list of URLs from the file
$urlList = Get-Content $urlListPath

# Iterate through the URLs and check each one on VirusTotal
foreach ($url in $urlList) {
    # Encode the URL for use in the API request
    $encodedUrl = [System.Uri]::EscapeDataString($url)

    # Construct the API request URL
    $apiUrl = "https://www.virustotal.com/vtapi/v2/url/report?apikey=$apiKey&resource=$encodedUrl"

    # Send the API request and decode the response JSON
    $response = Invoke-RestMethod $apiUrl
    $json = $response | ConvertTo-Json

    # Check if the URL is marked as malicious
    if ($json.positives -gt 0) {
        Write-Host "$url is malicious!"
    }
    else {
        Write-Host "$url is clean."
    }
}
