from scapy.arch.windows import get_windows_if_list
from abc import ABC, abstractmethod
from scapy.layers.inet import IP
from scapy.all import sniff
from tkinter import font
from tkinter import *
import subprocess
import threading
import tkinter
import socket
import re

class NetworkAnalyzer(ABC):
    def __init__(self):
        self._Interfaces = get_windows_if_list()

    @abstractmethod
    def PacketCallback(self, packet):
        pass

    def GetSpecificDetails(self, Interface):
        self.Details = {
            'Name': Interface.get('name', 'N/A'),
            'Description': Interface.get('description', 'N/A'),
        }
        return self.Details

    def GetFilteredInterfaces(self):
        try:
            self.FilteredInterfaces = [self.GetSpecificDetails(Interface) for Interface in self._Interfaces]
            return self.FilteredInterfaces

        except Exception as Error:
            print(f"ERROR RETRIEVING NETWORK INTERFACES: {Error}")

    @abstractmethod
    def GetNetworkInterfaces(self, ParaName, ParaDuration):
        pass

class LocalIp:
    def GetLocalIp(self):
        # Get The IP Address Of Your Device.
        try:
            # Create a socket to get the local IP address
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as IpGetter:
                IpGetter.connect(("8.8.8.8", 80))
                Local_Ip = IpGetter.getsockname()[0]
            return (f"YOUR LOCAL IP ADDRESS IS: {Local_Ip}")

        except socket.error as Error:
            return (f"FAILED TcreateO RETRIEVE LOCAL IP ADDRESS: {Error}")

class DefaultGateway:
    def GetDefaultGateway(self):
        # Get The Default Gateway Of Your Device.
        try:
            self.__Result = subprocess.check_output(["ipconfig", "/all"]).decode("utf-8")
            self.DefaultGatewayFinder = re.search(r"Default Gateway.*?(\d+\.\d+\.\d+\.\d+)", self.__Result)

            if self.DefaultGatewayFinder:
                return (f"YOUR DEFAULT GATEWAY IS: {self.DefaultGatewayFinder.group(1)}")

        except subprocess.CalledProcessError as Error:
            return (f"FAILED TO RETRIEVE DEFAULT GATEWAY: {Error}")

class SubnetMask:
    def GetSubnetMask(self):
        # Get The Subnet Mask Of Your Device.
        try:
            self.__Result = subprocess.check_output(["ipconfig", "/all"]).decode("utf-8")
            self.SubnetMask = re.search(r"Subnet Mask.*?(\d+\.\d+\.\d+\.\d+)", self.__Result)

            if self.SubnetMask:
                return (f"YOUR SUBNET MASK IS: {self.SubnetMask.group(1)}")

        except subprocess.CalledProcessError as Error:
            return (f"FAILED TO RETRIEVE SUBNET MASK: {Error}")

class TrafficSniffer(NetworkAnalyzer):
    def __init__(self):
        NetworkAnalyzer.__init__(self)

        self.Malicious_IPs_01 = [
            "100.12.194.201", "100.15.248.103", "104.192.3.74", "109.70.100.65", "136.158.8.40",
            "184.189.106.38", "185.243.218.110", "192.42.116.174", "192.42.116.176", "192.42.116.178",
            "192.42.116.184", "192.42.116.186", "192.42.116.187", "192.42.116.188", "198.96.155.3",
            "23.137.251.61", "24.120.113.134", "24.34.90.77", "2a0b:f4c2:1::1", "35.148.64.16",
            "38.64.49.3", "38.70.255.174", "45.134.225.36", "47.151.33.165", "47.180.50.150",
            "73.252.248.216", "76.106.124.188", "80.67.167.81", "98.254.174.23", "98.97.0.183",
            "45.134.89.122", "43.134.118.160", "37.143.128.26", "192.241.232.10", "103.110.87.70",
            "218.92.0.107", "114.132.220.22", "43.131.254.249", "49.247.198.162", "196.189.21.247",
            "218.92.0.113", "43.134.161.86", "193.105.134.95", "218.92.0.34", "218.92.0.27",
            "77.75.72.26", "79.175.189.245", "40.92.15.68", "201.249.89.102", "218.92.0.113"
        ]

        self.Malicious_IPs_02 = [
            "149.50.96.22", "222.186.16.210", "165.232.46.80", "80.82.77.139", "222.186.16.201",
            "183.98.92.44", "222.186.16.162", "80.82.77.33", "85.209.11.47", "185.196.10.78",
            "85.209.11.25", "222.186.16.196", "175.206.203.7", "85.209.11.227", "85.209.11.226",
            "179.43.163.130", "68.183.108.31", "66.240.219.146", "85.209.11.56", "151.177.13.62",
            "71.6.135.131", "2.56.247.174", "185.11.61.234", "207.90.244.6", "23.129.64.221",
            "45.95.147.172", "222.186.16.178", "161.35.71.130", "222.186.16.214", "85.209.11.44",
            "118.123.105.85", "121.153.49.22", "218.92.0.34", "218.92.0.31", "104.248.143.84",
            "186.67.248.6", "167.99.57.109", "162.142.125.223", "162.142.125.222", "218.92.0.76",
            "200.98.200.109", "185.220.101.8", "218.92.0.56", "59.49.77.211", "143.198.151.183",
            "61.177.172.136", "59.2.52.122", "103.251.167.20", "185.180.143.73", "222.186.16.186",
            "80.67.167.81", "72.240.125.133", "212.70.149.150", "218.92.0.107", "125.141.139.29",
            "61.177.172.179", "167.94.146.59", "185.142.236.34", "93.174.95.106", "121.133.103.211",
            "222.186.16.207", "64.227.190.195", "167.248.133.50", "61.177.172.140", "50.225.176.238",
            "161.35.231.77", "218.92.0.29", "218.92.0.22", "218.92.0.25", "218.92.0.24", "218.92.0.27",
            "216.167.191.198", "185.224.128.160", "192.155.88.231", "167.94.138.127", "61.177.172.160",
            "80.67.172.162", "109.107.183.195", "14.43.128.6", "222.168.30.19", "222.186.16.180",
            "218.92.0.112", "218.92.0.113", "218.92.0.118", "185.180.143.47", "185.165.190.17",
            "71.6.165.200", "180.101.88.197", "180.101.88.196", "180.101.88.198", "20.244.134.31",
            "220.120.48.109", "183.103.220.50", "94.182.85.131", "61.153.208.38", "211.218.194.133",
            "185.74.4.17", "121.129.194.210", "61.81.161.85", "220.92.14.245", "170.64.185.42",
            "159.65.127.234", "185.180.143.148", "182.93.7.194", "139.162.190.203", "211.253.10.96",
            "134.209.97.29", "172.104.11.34", "90.226.196.76", "118.70.180.188", "101.251.197.238",
            "193.23.55.134", "221.226.39.202", "64.62.197.12", "91.144.20.198", "164.90.166.150",
            "211.112.187.197", "124.230.124.250", "221.160.106.244", "114.199.123.211", "45.95.146.52",
            "185.220.102.244", "185.220.102.245", "185.220.102.243", "157.245.98.245", "170.64.181.20",
            "85.51.24.68", "114.206.23.151", "45.33.80.243", "103.228.37.59", "118.201.79.222",
            "64.227.126.250", "45.79.181.179", "103.56.61.144", "162.142.125.224", "162.142.125.226",
            "85.209.11.27", "31.186.48.216", "222.118.29.221", "220.88.1.208", "138.68.9.83",
            "34.168.181.171", "121.166.72.31", "172.104.11.51", "171.25.193.78", "185.239.106.91",
            "167.248.133.36", "167.248.133.37", "167.248.133.35", "167.248.133.38", "101.35.255.83",
            "1.11.62.189", "65.49.1.37", "112.145.45.11", "212.23.214.137", "164.77.117.10",
            "222.186.16.198", "218.154.141.54", "180.76.183.123", "71.6.146.186", "71.6.146.185",
            "103.146.50.194", "34.91.0.68", "178.20.55.16", "178.154.209.177",
        ]

        self.Malicious_IPs_03 = [
            "186.10.125.209", "124.221.148.89", "188.149.185.45", "206.189.145.158", "185.180.143.74",
            "164.92.120.218", "178.128.223.183", "94.254.0.234", "96.67.59.65", "218.92.0.53",
            "198.96.155.3", "164.92.160.177", "112.157.216.32", "119.201.206.141", "175.207.13.22",
            "201.116.3.194", "185.220.102.7", "185.220.102.8", "51.15.140.163", "195.19.105.60",
            "185.246.188.74", "45.129.14.120", "118.193.16.50", "167.94.138.50", "180.64.115.229",
            "43.129.40.155", "207.154.245.82", "111.68.98.152", "198.235.24.176", "125.19.235.76",
            "162.243.151.36", "195.144.21.56", "71.6.199.23", "125.99.173.162", "189.6.45.130",
            "164.177.31.66", "36.139.63.59", "45.43.33.218", "207.90.244.5", "185.180.143.11",
            "167.94.138.36", "23.129.64.223", "162.142.125.12", "50.192.223.205", "185.220.103.120",
            "159.203.102.122", "172.104.11.4", "96.77.25.60", "45.79.128.205", "97.74.91.196",
            "167.94.146.57", "107.175.33.240", "167.94.138.49", "45.129.14.166", "71.6.134.232",
            "71.6.134.231", "71.6.134.235", "71.6.134.234", "203.205.37.233", "59.173.19.11",
            "36.110.228.254", "27.72.155.116", "171.212.103.245", "118.123.105.93", "125.76.228.194",
            "218.91.157.54", "159.65.128.16", "96.69.13.140", "171.25.193.234", "162.142.125.11",
            "162.142.125.10", "143.110.189.97", "140.249.206.244", "192.155.90.220", "74.82.47.3",
            "74.82.47.4", "167.248.133.51", "112.161.214.48", "185.68.145.163", "71.6.146.130",
            "172.105.128.11", "172.105.128.13", "203.205.37.224", "221.162.13.2", "45.79.181.223",
            "185.233.100.23", "121.15.4.92", "1.13.255.185", "190.181.4.12", "167.248.133.185",
            "167.248.133.189", "34.131.36.46", "167.94.138.124", "167.94.138.125", "167.94.138.126",
            "43.153.61.139", "119.203.230.19", "200.11.141.86", "43.154.183.138", "185.56.83.83",
            "114.67.110.206", "185.220.102.253", "119.202.241.52", "148.135.75.51", "200.108.143.6",
            "125.212.233.50", "185.224.128.142", "103.228.37.47", "172.104.11.46", "95.130.227.116",
            "159.65.174.200", "162.142.125.216", "112.164.236.13", "221.162.209.158", "89.208.104.119",
            "43.131.35.111", "81.26.201.8", "36.137.22.65", "207.90.244.14", "128.14.209.38",
            "178.128.215.16", "200.70.56.202", "183.62.20.2", "184.105.247.252", "184.105.247.254",
            "134.209.168.219", "159.65.149.59", "58.56.23.210", "190.144.14.170", "170.64.189.43",
            "41.191.116.18", "111.217.204.48", "150.158.95.181", "185.129.61.7", "185.129.62.62",
            "65.49.20.66", "65.49.20.69", "43.156.76.206", "185.235.146.29", "128.199.71.12",
            "185.165.190.34", "43.153.39.12", "185.245.41.79", "43.134.41.93", "121.172.35.210",
            "104.236.64.158", "45.79.181.104", "59.36.138.46", "59.4.9.69", "43.129.33.99",
            "167.99.141.170", "167.248.133.125", "103.66.16.46", "137.184.38.234", "82.102.21.134",
            "62.28.222.221", "202.21.123.196", "41.77.11.130", "43.153.215.191", "85.209.11.254",
            "154.68.39.6", "103.200.30.126", "185.246.188.67", "118.193.36.81", "185.142.236.36",
            "43.155.145.252", "172.96.227.178", "162.243.146.70", "92.50.249.166", "134.209.147.59",
            "43.159.200.220", "192.241.219.38", "129.226.215.152", "121.186.179.1", "181.204.214.130",
            "167.94.145.57", "198.235.24.57", "45.89.25.8", "61.77.132.2", "68.116.41.2", "43.254.158.178",
            "45.79.172.21"
        ]

        # This Dataset Has Been Created by Adding Together Three Lists. These Three Lists Contain Malicious
        # IP Addresses. We Will Use This Large Dataset To Identify Malicious Ip Addresses During The Process
        # Of Network Traffic Analysis.
        self.Large_Dataset = self.Malicious_IPs_01 + self.Malicious_IPs_02 + self.Malicious_IPs_03

        self.SelectedInterface = ""

    def GetGUINetworkInterface(self):
        self.ReturnNetworkInterfaces = NetworkAnalyzer.GetFilteredInterfaces(self)
        return self.ReturnNetworkInterfaces

    def Is_Malicious_IP_Address(self, IpAddress):
        # Check if the provided IP address is in the list of known malicious IPs
        return IpAddress in self.Large_Dataset

    def PacketCallback(self, packet):
        # The Callback function will print the source and destination IP addresses of captured
        # packets and also write them to text file.
        if packet.haslayer(IP):
            SourceIP = packet[IP].src
            DestinationIP = packet[IP].dst

            # Check if either source or destination IP is malicious
            if self.Is_Malicious_IP_Address(str(SourceIP)) or self.Is_Malicious_IP_Address(str(DestinationIP)):
                print(f"WARNING: MALICIOUS IP DETECTED! IP Packet: {SourceIP} -> {DestinationIP}")

                with open("Captured_Traffic.txt", "a") as TxtFile:
                    TxtFile.write(f"WARNING: MALICIOUS IP DETECTED! IP Packet: {SourceIP} -> {DestinationIP}\n")

            else:
                with open("Captured_Traffic.txt", "a") as TxtFile:
                    TxtFile.write(f"IP Packet: {SourceIP} -> {DestinationIP}\n")

                print(f"IP Packet: {SourceIP} -> {DestinationIP}")

    def GetNetworkInterfaces(self, ParaName, ParaDuration):
        self.__Raw_Interfaces = []

        for IterationVar, InterfaceDict in enumerate(self._Interfaces, 1):
            self.__RawStr = str(InterfaceDict)
            self.__Raw_Interfaces.append(self.__RawStr)

        try:
            # Take User's Choice Of Interface As Input.
            self.Name = str(ParaName)
            print("-" * 75)

            # Flag To Verify If The Interface Is Found Or Not.
            self.Interface_Found = False
            for String in self.__Raw_Interfaces:
                if (self.Name.lower() in String.lower()):
                    self.SelectedInterface = self.Name
                    self.Interface_Found = True
                    # Print The Network Name Of The Selected Interface.
                    print(f"YOUR SELECTED INTERFACE: {self.SelectedInterface}")
                    break

            print("-" * 75)
            print("Ip Packet: Sender(Source IP) -> Receiver(Destination IP)")

            # Check To See If The Interface Was Not Found?
            if not self.Interface_Found:
                raise Exception("INVALID INTERFACE NAME! TRY AGAIN!")

        except Exception as Error:
            print(Error)

        try:
            print("-" * 75)
            self.CaptureDuration = int(ParaDuration)
            print("-" * 75)

        except ValueError:
            self.CaptureDuration = 60  # Default duration
            return ("INVALID INPUT! CAPTURE DURATION SET TO DEFAULT VALUE OF 60 SECONDS!")

        # Start Sniffing Traffic On User's Choice Of Network Using The Packet Callback Function.
        # Additionally, The 'store' Parameter Has Been Set To 'False' In Order To Avoid The Packets
        # Being Stored In The Memory. The `timeout` Parameter Has Been Introduced For Specifying The
        # Capture Duration. When The End Of Specified Capture Duration Is Reached The Program Will Stop
        # Returning Traffic Based On The 'timeout' Parameter.
        sniff(iface=self.SelectedInterface, prn=self.PacketCallback, store=False, timeout=self.CaptureDuration)

        # Break Out Of The Loop After The Traffic Capture Has Been Finished.
        return True

class TrafficSnifferUI(Tk):
    def __init__(self):
        super().__init__()

        # Variable To Store The Network Interface Name Before The User Specifies It.
        self.NameVar = ""

        # Variable To Store The Capture Duration Before The User Specifies It.
        self.DurationVar = -1

        # Main Window Title
        self.title("TRAFFIC SNIFFER")

        # To Open The Main Window Maximized.
        self.state('zoomed')

        # To Set The Minimum Size Of The Window.
        self.minsize(width=1273, height=660)

        # To Set The Background Of The Main Window.
        self.configure(bg="black")

        # Custom Font
        self.Custom_Font = font.Font(self, family="Consolas", size=11)

        # Label
        self.Title = Label(self, text="TRAFFIC SNIFFER", width=30, fg="cyan", bg="black",
                           font=("Consolas", 20, "bold"))
        self.Title.place(x=55, y=20)

        # Label
        self.TopNote = Label(self, text="!CLICK ON THE BUTTONS BELOW TO EXECUTE THE SPECIFIED OPERATIONS!", width=64,
                           fg="cyan", bg="black", font=("Consolas", 11))
        self.TopNote.place(x=30, y=70)

        # Button
        self.Button01 = Button(self, text="DISPLAY DEVICE'S IP ADDRESS", width=38,
                               command=self.Button01Command, fg="white", bg="navy")
        self.Button01.place(x=145, y=120)

        # Button
        self.Button02 = Button(self, text="DISPLAY NETWORK'S DEFAULT GATEWAY", width=38,
                               command=self.Button02Command, fg="white", bg="navy")
        self.Button02.place(x=145, y=155)

        # Button
        self.Button03 = Button(self, text="DISPLAY DEVICE'S SUBNET MASK", width=38,
                               command=self.Button03Command, fg="white", bg="navy")
        self.Button03.place(x=145, y=190)

        # Button
        self.Button04 = Button(self, text="DISPLAY NETWORK INTERFACE DETAILS", width=38,
                               command=self.Button04Command, fg="white", bg="navy")
        self.Button04.place(x=145, y=225)

        # Button
        self.Button05 = Button(self, text="DISPLAY SENT AND RECEIVED NETWORK TRAFFIC", width=38,
                               command=self.Button05Command, fg="white", bg="navy")
        self.Button05.place(x=145, y=260)

        # Button
        self.Button06 = Button(self, text="EXIT PROGRAM", width=38, command=self.Button06Command,
                               fg="white", bg="navy")
        self.Button06.place(x=145, y=295)

        # Text Box Widget
        self.Output = Text(self, height=40, width=85, wrap=tkinter.NONE, fg="lime", bg="midnight blue")
        self.Output.place(x=585, y=12)

        # Vertical Scrollbar
        Vertical_ScrollBar = Scrollbar(self, orient=tkinter.VERTICAL, command=self.Output.yview)
        Vertical_ScrollBar.place(x=1252, y=13, height=643)

        # Horizontal Scrollbar
        Horizontal_ScrollBar = Scrollbar(self, orient=tkinter.HORIZONTAL, command=self.Output.xview)
        Horizontal_ScrollBar.place(x=586, y=639, width=667)

        # Configure The Text Box Widget To Use The Scrollbars.
        self.Output.config(yscrollcommand=Vertical_ScrollBar.set, xscrollcommand=Horizontal_ScrollBar.set)

    # Function For Adding Functionality To The Button Command Parameter
    def Button01Command(self):
        Object01 = LocalIp()
        self.Output.delete(1.0, tkinter.END)
        self.Output.insert(tkinter.END, Object01.GetLocalIp() + "\n")

    # Function For Adding Functionality To The Button Command Parameter
    def Button02Command(self):
        Object02 = DefaultGateway()
        self.Output.delete(1.0, tkinter.END)
        self.Output.insert(tkinter.END, Object02.GetDefaultGateway() + "\n")

    # Function For Adding Functionality To The Button Command Parameter
    def Button03Command(self):
        Object03 = SubnetMask()
        self.Output.delete(1.0, tkinter.END)
        self.Output.insert(tkinter.END, Object03.GetSubnetMask() + "\n")

    # Function For Adding Functionality To The Button Command Parameter
    def Button04Command(self):
        Object04 = TrafficSniffer()
        List = Object04.GetGUINetworkInterface()
        self.Output.delete(1.0, tkinter.END)
        for IterationVar, InterfaceDict in enumerate(List, 1):
            String = str(InterfaceDict)
            self.Output.insert(tkinter.END, str(IterationVar) + ")" + String + "\n")

    # The Callback Function Will Print The Source And Destination Ip Addresses Of Capture Traffic
    # Packets And Also Append Them To A Text File.
    def PacketCallbackGUI(self, packet):
        # To Check Whether A Packet Has An IP Layer Or Not.
        if packet.haslayer(IP):
            SourceIP = packet[IP].src
            DestinationIP = packet[IP].dst

            # To Create An Object Of 'TrafficSniffer' Class.
            CheckIp = TrafficSniffer()

            # To Check If A Source Or Destination IP Is Malicious Or Not.
            if CheckIp.Is_Malicious_IP_Address(str(SourceIP)) or CheckIp.Is_Malicious_IP_Address(str(DestinationIP)):
                # To Display The Captured Traffic Into The Text Box Widget In The GUI.
                self.Output.insert(tkinter.END, f"WARNING: MALICIOUS IP DETECTED! IP Packet: {SourceIP} -> {DestinationIP}\n")

                # To Open A File And Write The Captured Traffic To That File.
                with open("Traffic_Log.txt", "a") as TxtFile:
                    TxtFile.write(f"WARNING: MALICIOUS IP DETECTED! IP Packet: {SourceIP} -> {DestinationIP}\n")
            else:
                # To Open A File And Write The Captured Traffic To That File.
                with open("Traffic_Log.txt", "a") as TxtFile:
                    TxtFile.write(f"IP Packet: {SourceIP} -> {DestinationIP}\n")

                # To Display The Captured Traffic Into The Text Box Widget In The GUI.
                self.Output.insert(tkinter.END, f"IP Packet: {SourceIP} -> {DestinationIP}\n")

            # To Move The Scrollbar Downwards As New Traffic Capture Data Is Appended to It.
            self.Output.see(tkinter.END)

    def Push_Traffic_To_UI(self, ParaName, ParaDuration):
        # To Clear The Console.
        self.Output.delete(1.0, tkinter.END)

        # To Get The Details Of Every Network Interface Associated With The System.
        self.__Interfaces = get_windows_if_list()

        # In This Variable, We Have Assigned The Value For Interface Name That The User Will Input
        # In The Entry Widget On The Interface Screen.
        self.Name = str(ParaName)

        # This Is A Flag To Verify Whether The User's Provided Network Interface Name Was Found In The
        # List Of Dictionaries Of Network Interface Details.
        self.Interface_Found = False

        # Loop To Iterate Over The List That Contains Dictionaries Containing Network Interface Details.
        for InterfaceDict in self.__Interfaces:
            if (self.Name.lower() == InterfaceDict["name"].lower()):
                self.SelectedInterface = self.Name
                self.Interface_Found = True
                break

        # Check To See If The Provided Interface Name Was Found Or Not?
        if self.Interface_Found:
            # Print The Network Name Of The Selected Interface.
            self.Output.insert(tkinter.END, ("-" * 75) + "\n")
            self.Output.insert(tkinter.END, f"YOUR SELECTED INTERFACE: {self.SelectedInterface}\n")
            self.Output.insert(tkinter.END, ("-" * 75) + "\n")
            self.Output.insert(tkinter.END, "Ip Packet: Sender(Source IP) -> Receiver(Destination IP)\n")
            self.Output.insert(tkinter.END, ("-" * 75) + "\n")

            # Try Except Block To Catch Exceptions (Value Error In This Case) If The 'CaptureDuration'
            # Variable Throws Any Exceptions.
            try:
                self.CaptureDuration = int(ParaDuration)
            except ValueError:
                self.CaptureDuration = 60  # Default duration
                self.Output.insert(tkinter.END, f"INVALID INPUT! CAPTURE DURATION SET TO DEFAULT VALUE OF 60 SECONDS!\n")
                self.Output.insert(tkinter.END, ("-" * 75) + "\n")

            # Start Sniffing Traffic On User's Choice Of Network Using The Packet Callback Function.
            # Additionally, The 'store' Parameter Has Been Set To 'False' In Order To Avoid The Packets
            # Being Stored In The Memory. The `timeout` Parameter Has Been Introduced For Specifying The
            # Capture Duration. When The End Of Specified Capture Duration Is Reached The Program Will Stop
            # Returning Traffic Based On The 'timeout' Parameter.
            Sniffer_Thread = threading.Thread(target=self.Start_Sniffing,
                                              args=(
                                                  self.SelectedInterface, self.PacketCallbackGUI, self.CaptureDuration
                                                    )
                                              )
            Sniffer_Thread.start()

        elif not self.Interface_Found:
            self.Output.delete(1.0, tkinter.END)
            self.Output.insert(tkinter.END, f"INVALID INTERFACE NAME! TRY AGAIN!\n")
            return -1

    # Function To Start The Traffic Sniffing Process In A Separate Thread In Order To Avoid Any Lag Or
    # Unresponsiveness Of The Program.
    def Start_Sniffing(self, InterfaceName, PacketCallback, CaptureDuration):
        try:
            sniff(iface=InterfaceName, prn=PacketCallback, store=False, timeout=CaptureDuration)

        except Exception as Error:
            print(f"ERROR DURING NETWORK TRAFFIC CAPTURE: {Error}\n")
            return -1

    # Function For Adding Functionality To The Button Command Parameter
    def Button05Command(self):
        # Label
        self.Heading = Label(self, text="!!!!TRAFFIC SNIFFER PROCESS INITIATED!!!!", bg="black",
                             fg="green", font=("Consolas", 16, "bold"))
        self.Heading.place(x=40, y=340)

        # Label
        self.Warning_Msg = Label(self, text="NOTE: NETWORK NAMES ARE CASE-SENSITIVE! USE 'DISPLAY NETWORK\n"
                                            "INTERFACE DETAILS'  BUTTON  TO CHECK  THE NETWORK  INTERFACE\n"
                                            "NAMES THAT ARE ASSOCIATED WITH YOUR DEVICE  BEFORE  ENTERING\n"
                                            "THE NETWORK NAME!",
                                 height=4, width=60, justify="left", bg="black", fg="gold",
                                 font=("Consolas", 12))
        self.Warning_Msg.place(x=19, y=380)

        #Label
        self.Label_Name = Label(self, text="ENTER NETWORK'S NAME HERE -->", height=1, width=30,
                                font=self.Custom_Font, bg="black", fg="red")
        self.Label_Name.place(x=46, y=477)

        # Entry
        self.Name_Entry = tkinter.Entry(self, width=37, fg="pale green", bg="midnight blue")
        self.Name_Entry.place(x=294, y=480)

        # Label
        self.Label_Duration = Label(self, text="ENTER CAPTURE DURATION IN SECONDS HERE -->", height=1,
                                    width=41, font=self.Custom_Font, bg="black", fg="red")
        self.Label_Duration.place(x=54, y=507)

        # Entry
        self.Duration_Entry = tkinter.Entry(self, width=20, fg="pale green", bg="midnight blue")
        self.Duration_Entry.place(x=396, y=510)

        # Button
        self.Submit_Button = Button(self, text="SUBMIT THE ENTERED VALUES", width=30,
                                    command=self.NameDurationGetter, fg="white", bg="navy")
        self.Submit_Button.place(x=175, y=540)

    # Function To Retrieve User's Input Of Network Interface Name And Traffic Capture Duration
    # Using The 'get()' Method.
    def NameDurationGetter(self):
        self.NameVar = self.Name_Entry.get()
        self.DurationVar = self.Duration_Entry.get()
        self.Push_Traffic_To_UI(self.NameVar, self.DurationVar)

    # Function For Adding Functionality To The Button Command Parameter
    def Button06Command(self):
        exit(0)


if __name__ == "__main__":
    # To Create An Object Of The 'TrafficSnifferGUI' Class.
    GUI_Initializer = TrafficSnifferUI()
    # To Run The Program's Loop.
    GUI_Initializer.mainloop()