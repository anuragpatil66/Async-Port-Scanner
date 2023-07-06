# Done by Anurag Patil - https://www.linkedin.com/in/anurag-patil-2a9b0022a/

import asyncio  # Importing the asyncio library for asynchronous programming
import socket  # Importing the socket library for network communication
import nmap  # Importing the nmap library for network scanning
import json  # Importing the json library for working with JSON data
import csv  # Importing the csv library for working with CSV files
import re  # Importing the re library for regular expression matching

"""
identify_service(target_ip, port): This function takes a target IP address and a port number as input and tries to identify the service associated with that port. It does this by calling the socket.getservbyport() function, which returns the service name based on the port number. If an OSError occurs, indicating that the service could not be identified, it returns the string "Unknown" as the service name.
"""
async def identify_service(target_ip, port):
    try:
        service_name = socket.getservbyport(port)  # Retrieve the service name associated with the specified port
        return service_name  # Return the service name
    except OSError:
        return "Unknown"  # If an OSError occurs, return "Unknown" as the service name

"""
identify_os(target_ip): This function takes a target IP address as input and uses the nmap.PortScanner class to scan the IP address and identify the operating system. It scans the target IP using the -O argument, which instructs Nmap to perform OS detection. It then retrieves the name of the identified operating system from the scan results and returns it.
"""
async def identify_os(target_ip):
    scanner = nmap.PortScanner()  # Create a new instance of the PortScanner class from the nmap library
    scanner.scan(target_ip, arguments='-O')  # Scan the specified target IP address to identify the operating system
    os_info = scanner[target_ip]['osmatch'][0]['name']  # Retrieve the name of the identified operating system
    return os_info  # Return the operating system name

"""
scan_port(target_ip, port): This function takes a target IP address and a port number as input and performs a port scan on the specified IP address and port. It uses the asyncio.open_connection() function to open a connection to the target IP and port. It waits for the connection to be established with a timeout of 1 second using asyncio.wait_for(). 
If the connection is successful, it closes the writer and waits for it to be fully closed. It then calls the identify_service() function to identify the service associated with the opened port. If a service name is found, it prints the IP address, port, and service name. If no service name is found, it prints the IP address, port, and indicates that the port is not open. If a timeout or connection refused error occurs, it returns None. If any other exception occurs, it prints the IP address, port, and the exception that occurred, and returns a tuple with the IP address, and None values for port and service.
"""
async def scan_port(target_ip, port):
    try:
        connection = asyncio.open_connection(target_ip, port)  # Open a connection to the specified IP address and port
        _, writer = await asyncio.wait_for(connection, timeout=1)  # Wait for the connection to be established with a timeout of 1 second
        writer.close()  # Close the writer
        await writer.wait_closed()  # Wait until the writer is fully closed

        service_name = await identify_service(target_ip, port)  # Identify the service associated with the opened port

        if service_name:  # If a service name is found
            print(f"IP: {target_ip}, Port: {port}, Service: {service_name}")  # Print the IP address, port, and service name
        else:  # If no service name is found
            print(f"IP: {target_ip}, Port: {port} - Port/Port Range not open, Service: NA")  # Print the IP address, port, and indicate that the port is not open

    except (asyncio.TimeoutError, ConnectionRefusedError):  # If a timeout or connection refused error occurs
        return None  # Return None
    except Exception as e:  # If any other exception occurs
        print(f"An exception occurred for IP {target_ip} and port {port}: {e}")  # Print the IP address, port, and the exception that occurred
        return (target_ip, None, None)  # Return a tuple with the IP address, and None values for port and service

"""
scan_ports(target_ips, port_range): This function takes a list of target IP addresses and a port range as input and performs port scanning on all combinations of target IP addresses and ports. It creates an empty list open_ports to store the open ports. It also creates an empty list tasks to store the tasks for scanning each IP address and port. It iterates over each target IP address and port in the given ranges and appends a task to the tasks list by calling the scan_port() function. It then uses asyncio.gather() to execute all the tasks concurrently and gather the results. The results are stored in the results list. It filters out the None results from results and stores the open ports in the open_ports list. Finally, it returns the open_ports list, which contains the list of open ports discovered during the scanning process.
"""
async def scan_ports(target_ips, port_range):
    open_ports = []  # Create an empty list to store open ports
    tasks = []  # Create an empty list to store tasks
    for target_ip in target_ips:  # Iterate over each target IP address
        for port in port_range:  # Iterate over each port in the port range
            tasks.append(scan_port(target_ip, port))  # Create a task to scan the specified IP address and port and add it to the tasks list

    results = await asyncio.gather(*tasks, return_exceptions=True)  # Execute all tasks concurrently and gather the results
    open_ports = [port for port in results if port is not None]  # Filter out the None results and store the open ports in the open_ports list

    return open_ports  # Return the list of open ports

"""
print_result(result): This function takes a result dictionary as input and prints the relevant information about the IP, open ports, and operating system (if available). It first prints a new line for formatting, then prints the IP address from the result dictionary. It prints the header for open ports. If the open_ports value is a string and equals "No open ports found.", it prints this message. Otherwise, it iterates over each port_info in open_ports and prints the IP, port, and service name. It retrieves the OS information from the result dictionary and, if available, prints it. Finally, it prints a horizontal line as a separator.
"""
def print_result(result):
    # Prints a new line for formatting
    print("\n")
    # Prints the IP address from the result dictionary
    print("IP:", result["IP"])
    # Prints the header for open ports
    print("Open ports:")
    # Retrieves the open ports from the result dictionary
    open_ports = result["Open ports"]
    # Checks if open_ports is a string indicating no open ports found
    if isinstance(open_ports, str) and open_ports == "No open ports found.":
        # Prints the message indicating no open ports found
        print(open_ports)
    else:
        # Iterates over each port_info in open_ports and prints IP, port, and service name
        for port_info in open_ports:
            ip, port, service_name = port_info
            print(f"IP: {ip}, Port: {port}, Service: {service_name}")
    # Retrieves the OS information from the result dictionary
    os_info = result.get("Operating System")
    # Checks if OS information is available
    if os_info:
        # Prints the OS information
        print("Operating System:", os_info)
    # Prints a horizontal line as a separator
    print("---------------------")

"""
scan_subnet(target_ip_range, port_range): This asynchronous function scans a subnet of IP addresses specified by target_ip_range for open ports within the port_range. It starts by initializing an empty list target_ips to store the target IPs. It splits the target_ip_range into parts based on periods and retrieves the base IP by joining the first three parts. It generates a list of target IPs by iterating from 1 to 255 and appending them to target_ips.
The function then initializes an empty list scan_results to store the scan results. It iterates over each target IP in target_ips. For each target IP, it performs a port scan using the scan_ports function by passing the target IP as a list and the port_range. The open ports obtained from the scan are stored in the open_ports variable. It creates a dictionary scan_result with the IP and open ports information.

If there are open ports (open_ports is not empty), it calls the identify_os function to identify the operating system (OS) of the target IP and adds the OS information to the scan_result dictionary. It appends a copy of the scan_result dictionary to the scan_results list. It then calls the print_result function to display the scan result.

Finally, the function returns the scan_results list containing all the scan results.
"""
async def scan_subnet(target_ip_range, port_range):
    # Initializes an empty list to store target IPs
    target_ips = []
    # Splits the target IP range into parts based on periods
    ip_parts = target_ip_range.split('.')
    # Retrieves the base IP by joining the first three parts
    base_ip = '.'.join(ip_parts[:3])

    # Generates a list of target IPs by iterating from 1 to 255 and appending to target_ips
    for i in range(1, 256):
        target_ip = f"{base_ip}.{i}"
        target_ips.append(target_ip)

    # Initializes an empty list to store the scan results
    scan_results = []
    # Iterates over each target IP in target_ips
    for target_ip in target_ips:
        # Performs a port scan on the target IP using scan_ports function
        open_ports = await scan_ports([target_ip], port_range)
        # Creates a dictionary to store the scan result
        scan_result = {
            "IP": target_ip,
            "Open ports": open_ports if open_ports else "No open ports found."
        }
        # Checks if open_ports is not empty (i.e., open ports are found)
        if open_ports:
            # Identifies the operating system (OS) of the target IP using identify_os function
            os_info = await identify_os(target_ip)
            # Adds the OS information to the scan result dictionary
            scan_result["Operating System"] = os_info
        # Appends a copy of the scan result dictionary to the scan_results list
        scan_results.append(scan_result.copy())

        # Calls the print_result function to display the scan result
        print_result(scan_result)

    # Returns the list of scan results
    return scan_results

"""
scan_single_ip(target_ip, port_range): This asynchronous function scans a single target IP specified by target_ip for open ports within the port_range. It performs a port scan using the scan_ports function by passing the target IP as a list and the port_range. The open ports obtained from the scan are stored in the open_ports variable. It creates a dictionary scan_result with the IP and open ports information.

If there are open ports (open_ports is not empty), it calls the identify_os function to identify the operating system (OS) of the target IP and adds the OS information to the scan_result dictionary. Finally, it returns a list containing the scan_result dictionary.
"""
async def scan_single_ip(target_ip, port_range):
    # Performs a port scan on the target IP using scan_ports function
    open_ports = await scan_ports([target_ip], port_range)
    # Creates a dictionary to store the scan result
    scan_result = {
        "IP": target_ip,
        "Open ports": open_ports if open_ports else "No open ports found."
    }
    # Checks if open_ports is not empty (i.e., open ports are found)
    if open_ports:
        # Identifies the operating system (OS) of the target IP using identify_os function
        os_info = await identify_os(target_ip)
        # Adds the OS information to the scan result dictionary
        scan_result["Operating System"] = os_info
    # Returns a list containing the scan result dictionary
    return [scan_result]

"""
scan_ip_range(start_ip, end_ip, port_range): This function takes a start IP address, end IP address, and port range as input. It initializes an empty list target_ips to store the target IP addresses. It extracts the first three parts of the start IP address using split('.')[:3] and joins them back together to form the base_ip. It also extracts the last part of the start and end IP addresses as integers using int(start_ip.split('.')[3]) and int(end_ip.split('.')[3]), respectively. It then iterates over a range from start_index to end_index + 1 and appends a target IP address to the target_ips list by combining the base_ip with the current index.

Inside the loop, it calls the scan_ports() function with the current target IP address and port range to perform port scanning. It creates a scan_result dictionary to store the scan result, including the target IP address and the open ports (or a message if no open ports were found). If there are open ports, it also calls the identify_os() function to identify the operating system of the target IP address and adds it to the scan_result. The scan_result is appended to the scan_results list, and the scan_result is printed using the print_result() function.

Finally, it returns the scan_results list containing all the scan results.
"""
async def scan_ip_range(start_ip, end_ip, port_range):
    target_ips = []  # Create an empty list to store the target IP addresses
    ip_parts = start_ip.split('.')[:3]  # Split the start IP address by periods and select the first three parts
    base_ip = '.'.join(ip_parts)  # Join the selected parts back together to form the base IP address

    start_index = int(start_ip.split('.')[3])  # Split the start IP address by periods and select the last part as an integer
    end_index = int(end_ip.split('.')[3])  # Split the end IP address by periods and select the last part as an integer

    for i in range(start_index, end_index + 1):  # Iterate over a range from start_index to end_index (inclusive)
        target_ip = f"{base_ip}.{i}"  # Create a target IP address by appending the current index to the base IP address
        target_ips.append(target_ip)  # Add the target IP address to the list of target IPs

    scan_results = []  # Create an empty list to store the scan results
    for target_ip in target_ips:  # Iterate over each target IP address
        open_ports = await scan_ports([target_ip], port_range)  # Perform port scanning on the current target IP address using the specified port range
        scan_result = {  # Create a dictionary to store the scan result
            "IP": target_ip,  # Store the target IP address
            "Open ports": open_ports if open_ports else "No open ports found."  # Store the open ports or a message if no open ports were found
        }
        if open_ports:  # If there are open ports
            os_info = await identify_os(target_ip)  # Identify the operating system of the target IP address
            scan_result["Operating System"] = os_info  # Store the operating system information in the scan result
        scan_results.append(scan_result.copy())  # Add a copy of the scan result to the scan_results list

        print_result(scan_result)  # Print the scan result

    return scan_results  # Return the list of scan results

"""
is_valid_ip(address): This function takes an address as input and uses a regular expression pattern r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$" to match a valid IP address format. It returns True if the address matches the IP address pattern, and False otherwise.
"""
def is_valid_ip(address):
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"  # Define a regular expression pattern to match a valid IP address
    return re.match(ip_pattern, address) is not None  # Check if the address matches the IP address pattern

"""
is_valid_ip_range(ip_range): This function takes an IP range as input and uses a regular expression pattern r"^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$" to match a valid IP range format. It returns True if the IP range matches the IP range pattern, and False otherwise.
"""
def is_valid_ip_range(ip_range):
    ip_range_pattern = r"^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"  # Define a regular expression pattern to match a valid IP range
    return re.match(ip_range_pattern, ip_range) is not None  # Check if the IP range matches the IP range pattern

"""
is_valid_subnet(subnet): This function takes a subnet as input and uses a regular expression pattern r"^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$" to match a valid subnet format. It returns True if the subnet matches the subnet pattern, and False otherwise.
"""
def is_valid_subnet(subnet):
    subnet_pattern = r"^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$"  # Define a regular expression pattern to match a valid subnet
    return re.match(subnet_pattern, subnet) is not None  # Check if the subnet matches the subnet pattern

"""
is_valid_port_range(port_range): This function takes a port range as input and uses a regular expression pattern r"^(?:\d+|\d+-\d+)(?:,(?:\d+|\d+-\d+))*$" to match a valid port range format. If the port range does not match the pattern, it returns False. Otherwise, it converts the port range string to a list of ports using the range_from_string() function and checks if all the ports are within the valid port range (between 1 and 65535). It returns True if the port range is valid, and False otherwise.
"""
def is_valid_port_range(port_range):
    port_range_pattern = r"^(?:\d+|\d+-\d+)(?:,(?:\d+|\d+-\d+))*$"  # Define a regular expression pattern to match a valid port range
    if not re.match(port_range_pattern, port_range):  # Check if the port range matches the port range pattern
        return False

    ports = range_from_string(port_range)  # Convert the port range string to a list of ports
    return all(1 <= port <= 65535 for port in ports)  # Check if all ports are within the valid port range

"""
is_valid_file_path(file_path, file_extension): This function takes a file path and a file extension as input. It uses a regular expression pattern to match a valid file path format with the specified file extension. It returns True if the file path matches the file path pattern, and False otherwise.
"""
def is_valid_file_path(file_path, file_extension):
    file_path_pattern = r"^(C:/|C:\\)(?:[A-Za-z0-9_-]+[/\\])+[A-Za-z0-9_-]+" + re.escape(file_extension) + "$"  # Define a regular expression pattern to match a valid file path with the specified file extension
    return re.match(file_path_pattern, file_path) is not None  # Check if the file path matches the file path pattern

"""
def range_from_string(range_string):: This line defines a function called range_from_string that takes a range_string as input and converts it into a list of port values.

ports = []: This line initializes an empty list called ports to store the port values extracted from the range_string.

range_list = range_string.split(","): This line splits the range_string by commas and creates a list called range_list containing individual range items.

for item in range_list:: This line starts a loop that iterates over each range item in the range_list.

if "-" in item:: This line checks if the current range item contains a hyphen ("-"), which indicates a range of ports.

start, end = item.split("-"): This line splits the range item by the hyphen and assigns the start and end values to the variables start and end, respectively.

ports.extend(range(int(start), int(end) + 1)): This line converts the start and end values to integers using int() and creates a range of ports (inclusive) using the range() function. The ports in the range are then added to the ports list using the extend() function.

else:: This line executes if the range item does not contain a hyphen, indicating a single port value.

ports.append(int(item)): This line converts the range item to an integer using int() and appends it to the ports list.

return ports: This line returns the ports list containing all the extracted port values.
"""
def range_from_string(range_string):
    ports = []  # Create an empty list to store the port values

    range_list = range_string.split(",")  # Split the range string by commas and create a list of individual range items

    for item in range_list:  # Iterate over each range item in the list
        if "-" in item:  # Check if the range item contains a hyphen (-) indicating a range of ports
            start, end = item.split("-")  # Split the range item by hyphen to get the start and end values
            ports.extend(range(int(start), int(end) + 1))  # Add the range of ports (inclusive) to the ports list using the extend() function
        else:  # If the range item does not contain a hyphen, it represents a single port value
            ports.append(int(item))  # Convert the port item to an integer and add it to the ports list

    return ports  # Return the list of port values

async def main():
    while True:
        # Display the welcome message
        print("------------------------------------------------------------ Welcome To Async Port Scanner -----------------------------------------------------------")

        # Display the scanning options
        print("=======================Scanning Options:====================")
        print("1. Scan a single IP")
        print("2. Scan an IP range")
        print("3. Scan a subnet")
        print("4. Terminate")

        # Prompt the user for their choice
        choice = input("Enter your choice (1, 2, 3, or 4): ")

        if choice == "1":
            # If the user chooses to scan a single IP
            target_ip = input("Enter the target IP address (e.g., 192.168.1.1): ")

            # Validate the target IP address
            while not is_valid_ip(target_ip):
                print("Invalid IP address. Please try again.")
                target_ip = input("Enter the target IP address (e.g., 192.168.1.1): ")

            port_range = input("Enter the ports or port range to scan (e.g., 45 or 25,34,80 or 1-65535): ")

            # Validate the port range format
            while not is_valid_port_range(port_range):
                print("Invalid port range format. Please try again.")
                port_range = input("Enter the ports or port range to scan (e.g., 45 or 25,34,80 or 1-65535): ")

            # Perform the scan on the single IP
            results = await scan_single_ip(target_ip, range_from_string(port_range))
            break

        elif choice == "2":
            # If the user chooses to scan an IP range
            start_ip = input("Enter the starting IP address (e.g., 192.168.1.1): ")
            end_ip = input("Enter the ending IP address (e.g., 192.168.1.6): ")

            # Validate the starting and ending IP addresses
            while not is_valid_ip(start_ip) or not is_valid_ip(end_ip):
                print("Invalid IP address. Please try again.")
                start_ip = input("Enter the starting IP address (e.g., 192.168.1.1): ")
                end_ip = input("Enter the ending IP address (e.g., 192.168.1.7): ")

            port_range = input("Enter the port range to scan (e.g., 45 or 25,34,80 or 1-65535): ")

            # Validate the port range format
            while not is_valid_port_range(port_range):
                print("Invalid port range format. Please try again.")
                port_range = input("Enter the port range to scan (e.g., 45 or 25,34,80 or 1-65535): ")

            # Perform the scan on the IP range
            results = await scan_ip_range(start_ip, end_ip, range_from_string(port_range))
            break

        elif choice == "3":
            # If the user chooses to scan a subnet
            target_ip_range = input("Enter the target IP range (e.g., 192.168.1.0/24): ")

            # Validate the subnet format
            while not is_valid_subnet(target_ip_range):
                print("Invalid subnet format. Please try again.")
                target_ip_range = input("Enter the target IP range (e.g., 192.168.1.0/24): ")

            port_range = input("Enter the port range to scan (e.g., 45 or 25,34,80 or 1-65535): ")

            # Validate the port range format
            while not is_valid_port_range(port_range):
                print("Invalid port range format. Please try again.")
                port_range = input("Enter the port range to scan (e.g., 45 or 25,34,80 or 1-65535): ")

            # Perform the scan on the subnet
            results = await scan_subnet(target_ip_range, range_from_string(port_range))
            break

        elif choice == "4":
            # If the user chooses to terminate the program
            print("Thank You For Using Async Port Scanner")
            return

        else:
            # If the user enters an invalid choice
            print("Invalid choice. Please try again.\n")

    print("\nScan Results:")  # Prints a header for the scan results
    for result in results:  # Iterates over each result in the 'results' list
        print("IP:", result["IP"])  # Prints the IP address of the result
        print("Open ports:")  # Prints a label for the open ports
        open_ports = result["Open ports"]  # Retrieves the open ports from the result
        if isinstance(open_ports, str) and open_ports == "No open ports found.":  # Checks if the open_ports is a string with the value "No open ports found."
            print(open_ports)  # Prints the message indicating no open ports
        else:
            for port_info in open_ports:  # Iterates over each port information in the open_ports list
                ip, port, service_name = port_info  # Unpacks the port information into variables
                print(f"IP: {ip}, Port: {port}, Service: {service_name}") # Prints the IP, port, and service name of an open port
        os_info = result.get("Operating System")  # Retrieves the operating system information from the result
        if os_info:
            print("Operating System:", os_info)  # Prints the operating system information if available
        print("---------------------")  # Prints a separator between each result

    while True:
        print("\nOutput Format:")  # Prints a header for the output format options
        print("1. JSON")  # Prints option 1 for JSON format
        print("2. CSV")  # Prints option 2 for CSV format
        print("3. Plain Text")  # Prints option 3 for plain text format
        print("4. Terminate")  # Prints option 4 to terminate the code
        output_format = input("Enter the output format (1, 2, 3, or 4): ") # Prompts the user to enter the desired output format (1, 2, 3, or 4)

        if output_format == "4":
            print("Terminating the code.")  # Prints a message indicating the code is being terminated
            return  # Exits the current function or program
        elif output_format in ["1", "2", "3"]:
            break  # Breaks the loop if the output format is valid
        else:
            print("Invalid output format. Please try again.\n")  # Prints an error message for an invalid output format

    valid_extensions = {
        "1": ".json",
        "2": ".csv",
        "3": ".txt"
    }

    file_extension = valid_extensions[output_format]  # Retrieves the file extension based on the output format
    file_path = input(f'Enter the "{file_extension[1:].upper()}" file path to save the results: ') # Prompts the user to enter the file path to save the results with the appropriate file extension
    

    while not is_valid_file_path(file_path, file_extension):
        if not file_path.endswith(file_extension): # Checks if the entered file path is valid based on the specified file extension
            print(f"Invalid file path. The file path should have the extension '{file_extension}'.") # Prints an error message indicating that the file path does not have the correct extension
            
        else:
            print(f"Invalid file path format. Please provide a valid file path in the format C:/Users/anura/Desktop/Ethical/result{file_extension} or C:\\Users\\anura\\Desktop\\Ethical\\result{file_extension}")  # Prints an error message indicating that the file path format is invalid
           
        file_path = input(f'Enter the "{file_extension[1:].upper()}" file path to save the results: ') # Prompts the user to enter a valid file path with the appropriate file extension

    save_results_to_file(results, file_path, output_format, file_extension) # Calls a function to save the scan results to a file, providing the results, file path, output format, and file extension as arguments

"""
range_from_string(port_range):
a)This function takes a string port_range as input, which represents a range or a comma-separated list of ports (e.g., "80, 8080-8090, 443").
b)It splits the port_range string using commas as the delimiter and stores the resulting range strings in the ranges list.
c)It initializes an empty set ports to store the individual ports.
d)It iterates over each range string in ranges.
e)If a range string contains a hyphen ("-"), indicating a range of ports, it splits the range string into start_port and end_port.
f)It uses the range function to generate a range of ports from start_port to end_port (inclusive) and adds them to the ports set using the update method.
g)If a range string doesn't contain a hyphen, it converts the string to an integer and adds it directly to the ports set using the add method.
h)Finally, it returns a sorted list of ports obtained by converting the ports set to a list.
"""
def range_from_string(port_range):
    ranges = port_range.split(",")  # Splits the port_range string into individual range strings
    ports = set()  # Creates an empty set to store the individual ports
    for r in ranges:
        if "-" in r:  # Checks if the range string contains a hyphen indicating a range of ports
            start_port, end_port = r.split("-")  # Splits the range string into start and end ports
            ports.update(range(int(start_port), int(end_port) + 1))  # Adds the ports within the range to the set
        else:
            ports.add(int(r))  # Adds a single port to the set
    return sorted(ports)  # Returns a sorted list of ports

"""
save_results_to_file(results, file_path, output_format, file_extension):

a)This function is responsible for saving the scan results to a file based on the specified output format.

b)It takes results (the scan results), file_path (the path where results should be saved), output_format (the format in which results should be saved), and file_extension (the file extension based on the output format) as inputs.

c)It starts by defining a dictionary valid_extensions that maps output format codes ("1", "2", "3") to their corresponding file extensions (".json", ".csv", ".txt").

d)It then retrieves the appropriate file_extension based on the output_format provided.

e)Next, it performs some checks on the file_path to ensure that it ends with the expected file_extension. If not, it prints an error message and returns from the function without saving anything.

f)Depending on the output_format, it handles the saving of results in different formats:

    i)If output_format is "1" (JSON):
        It opens the file in write mode ("w").
        It uses the json.dump function to write the results in JSON format to the file with indentation for readability.
        It prints a message indicating that the results have been saved in JSON format.
    ii)If output_format is "2" (CSV):
        It opens the file in write mode ("w") with newline="" to avoid adding extra blank lines between rows in the CSV.
        It creates a csv.writer object to write to the file.
        It writes the header row with the column names ("IP", "Port", "Service", "Operating System") to the CSV file.
        It iterates through each result and writes the IP, port, service name, and operating system information (if available) to separate rows in the CSV file.
    iii)If output_format is "3" (Plain Text):
        It opens the file in write mode ("w").
        It writes a header for the scan results.
        It iterates through each result and writes the IP address, open ports, and operating system information (if available) in plain text format to the file.
    iv)If output_format is "4", it means the user wants to terminate the code execution. The function prints a message indicating the termination.
g)The function save_results_to_file is called within an asyncio.run(main()) call, suggesting that it is part of an asynchronous main program logic, but the specific details of that program logic are not provided.
"""
def save_results_to_file(results, file_path, output_format, file_extension):
    valid_extensions = {
        "1": ".json",
        "2": ".csv",
        "3": ".txt"
    }

    file_extension = valid_extensions[output_format]  # Retrieves the file extension based on the output format
    
    if not file_path.endswith(file_extension):  # Checks if the file path does not end with the expected file extension
        print(f"Invalid file path. The file path should have the extension '{file_extension}'.")
        return  # Exits the function if the file path is invalid

    if output_format == "1":  # Checks if the output format is JSON
        with open(file_path, "w") as file:  # Opens the file in write mode
            json.dump(results, file, indent=4)  # Writes the results to the file in JSON format with indentation
        print(f"Results saved to {file_path} in JSON format.")
    elif output_format == "2":  # Checks if the output format is CSV
        with open(file_path, "w", newline="") as file:  # Opens the file in write mode, specifying no newline characters
            writer = csv.writer(file)  # Creates a CSV writer object
            writer.writerow(["IP", "Port", "Service", "Operating System"])  # Writes the header row to the CSV file
            for result in results:  # Iterates over each result
                ip = result["IP"]  # Retrieves the IP address from the result
                open_ports = result["Open ports"]  # Retrieves the open ports from the result
                if isinstance(open_ports, str) and open_ports == "No open ports found.":  # Checks if the open_ports is a string with the value "No open ports found."
                    writer.writerow([f"IP: {ip}, Port: No open ports found., Service: NA, Operating System: NA"])
                    # Writes a row indicating no open ports for the IP
                    writer.writerow(["\n"])  # Writes an empty row for separation
                else:
                    os_info = result.get("Operating System")  # Retrieves the operating system information
                    for port_info in open_ports:  # Iterates over each port information in the open_ports list
                        _, port, service_name = port_info  # Unpacks the port information into variables
                        writer.writerow([f"IP: {ip}, Port: {port}, Service: {service_name}, Operating System: {os_info}"]) # Writes a row with the IP, port, service name, and operating system information
                        writer.writerow(["\n"])  # Writes an empty row for separation
        print(f"Results saved to {file_path} in CSV format.")
    elif output_format == "3":  # Checks if the output format is plain text
        with open(file_path, "w") as file:  # Opens the file in write mode
            file.write("Scan Results:\n\n")  # Writes a header for the scan results
            for result in results:  # Iterates over each result
                file.write(f"IP: {result['IP']}\n")  # Writes the IP address of the result
                file.write("Open ports:\n")  # Writes a label for the open ports
                open_ports = result["Open ports"]  # Retrieves the open ports from the result
                if isinstance(open_ports, str) and open_ports == "No open ports found.":
                    file.write(f"{open_ports}\n")  # Writes the message indicating no open ports
                else:
                    for port_info in open_ports:  # Iterates over each port information in the open_ports list
                        ip, port, service_name = port_info  # Unpacks the port information into variables
                        file.write(f"IP: {ip}, Port: {port}, Service: {service_name}\n") # Writes the IP, port, and service name of an open port
                os_info = result.get("Operating System")  # Retrieves the operating system information
                if os_info:
                    file.write(f"Operating System: {os_info}\n")  # Writes the operating system information if available
                file.write("---------------------\n")  # Writes a separator between each result
        print(f"Results saved to {file_path} in plain text format.")
        print("Thank You For Using Async Port Scanner")
    elif output_format == "4":  # Checks if the output format is to terminate the code
        print("Thank You For Using Async Port Scanner")
        return  # Exits the function

asyncio.run(main())  # Calls the main function asynchronously
