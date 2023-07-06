# Done by Anurag Patil - https://www.linkedin.com/in/anurag-patil-2a9b0022a/
# Async-Port-Scanner
Unleash the Power of Networks! Lightning-fast asynchronous scanning and service identification for all your cybersecurity exploration needs.

The AsyncPortScanner is a powerful tool for scanning network ports and identifying services running on target IP addresses. It utilizes asynchronous programming techniques to efficiently scan multiple IPs and ports simultaneously, providing fast and accurate results.

The main features of AsyncPortScanner include:

Port Scanning: The scanner allows you to scan a single IP, an IP range, or an entire subnet. It supports both individual ports and port ranges (Max 65535 Ports).

Service Identification: The tool identifies the services running on open ports by querying the service name associated with each port using the getservbyport() function.

Operating System Identification: In addition to service identification, AsyncPortScanner can also determine the operating system of the target IP using the Nmap PortScanner library. It utilizes the -O argument to retrieve OS information.

Output Formats: The scanner provides multiple output formats for displaying and saving scan results. It supports JSON, CSV, and plain text formats, allowing you to choose the most convenient format for your needs.

Error Handling: The tool gracefully handles exceptions, such as connection timeouts and refused connections, and provides informative error messages for troubleshooting.

The AsyncPortScanner offers flexibility, speed, and reliability in network port scanning tasks. It is a valuable tool for network administrators, security professionals, and developers working with network-related applications.

Note: Due to character limitations, the full explanation of the code couldn't be provided here. Please refer to the code documentation and comments for a detailed explanation of each function and its usage.

Feel free to use and contribute to the AsyncPortScanner project, and happy scanning!
