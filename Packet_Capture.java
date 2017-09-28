/**
 *
 * @author Ayush
 * Completed: 24th March, 2016
 */

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.tcpip.Http;


public class Packet_Capture {
    
    public static void main(String[] args) throws IOException{
    
    List<PcapIf> alldevs = new ArrayList<PcapIf>();  //Will Fill up details of Network Interface Cards
    StringBuilder err = new StringBuilder();  //For giving Error Messages
    
    //Pcap.findAllDevs is used to retrieve list of interfaces
    
    int r = Pcap.findAllDevs(alldevs, err);
    if(r == Pcap.NOT_OK || alldevs.isEmpty())
    {
     System.err.printf("Error reading list of devices. Error is %s: ",err.toString());
    }
    else{
        System.out.println("Network Devices Found:\n");
    }
    
    //getname() and getDescription() methods are used 
    int i=1;
    for(PcapIf device: alldevs){
        byte[] mac = device.getHardwareAddress();
        if(mac == null){
            continue; //Interface doesn't have a hardware 
        }
        String description = (device.getDescription());
        System.out.printf("**************************************************************\n%d. Name: %s\n   Description: %s\n   MAC Address: %s\n", i++, device.getName(),description, mac_string(mac));
            }
        System.out.printf("**************************************************************");
    
       
    //We will now ask User to select an interface.
    System.out.print("\nChoose the interface: ");
    Scanner in = new Scanner(System.in);
    int ans = Integer.parseInt(in.nextLine()); //Changing scanner into integer
    ans--;
    
    //Acquiring name of the interface for the system
    PcapIf device = alldevs.get(ans);
    System.out.printf("User selected interface: %s\n", device.getDescription());
    
    //We will now open the Interface selected by the user using Pcap.openLive()
    int snaplen = 64 * 1024;  //amount of data for each frame to be captured
    int flags = Pcap.MODE_PROMISCUOUS;  //allows to pass all traffic to the CPU
    int timeout = 10 * 1000;  //This is 10 milliseconds
    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, err);
    
    if(pcap == null){
        System.err.printf("Error while opening device for capture: " + err.toString());
        return;
    }
    
    //Ask user to select the filter
    System.out.print("\nFILTER OPTIONS:\n1. TCP\n2. UDP\n3. HTTP\n4. Exit\nChoose your option: ");
    Scanner s = new Scanner(System.in);
    int o = Integer.parseInt(s.nextLine());
    
    
    //We will setup a packet handler
    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
           
            public void nextPacket(PcapPacket packet, String user) {  
                
                Ip4 ip = new Ip4();         //Creating instance of Ipv4
                Tcp tcp = new Tcp();        //Creating instance of TCP
                Udp udp = new Udp();        //Creating instance of UDP
                Icmp icmp = new Icmp();     //Creating instance of ICMP
                Http hp = new Http();       //Creating instance of Http
                
                /*
                We will get our Ip address in bytes
                Each ip address contains 4 bytes or 32 bits ie 1 byte = 8 bits
                Format: X.X.X.X 
                */
                byte[] dIP= new byte[4], sIP=new byte[4];
                if (packet.hasHeader(ip)){
                    dIP = packet.getHeader(ip).destination(); //store destination ip address    
                    sIP= packet.getHeader(ip).source(); //store source ip address
                }
                else
                    return;
                
                String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP); //changing to string
                String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP); //changing to string
                
                switch(o){
                
                    case 1: 
                        if(packet.hasHeader(tcp)){
                            System.out.println("**************************************************");
                            System.out.printf("Received Packet: %s\nProtocol Name: TCP\nLength: %-4d\nSource: %d\nDestination: %d\nSource IP: %s\nDestination IP: %s\n", new Date(packet.getCaptureHeader().timestampInMillis()),packet.getCaptureHeader().wirelen(), tcp.source(), tcp.destination(),sourceIP,destinationIP);
                            
                        }
                        break;
                    
                    case 2:
                        if(packet.hasHeader(udp)){
                            System.out.println("**************************************************");
                            System.out.printf("Received Packet: %s\nProtocol Name: UDP\nLength: %-4d\nSource: %d\nDestination: %d\nSource IP: %s\nDestination IP: %s\n", new Date(packet.getCaptureHeader().timestampInMillis()),packet.getCaptureHeader().wirelen(), udp.source(), udp.destination(),sourceIP,destinationIP);
                            
                        }
                        break;
                                            
                    case 3:
                        if(packet.hasHeader(hp)){
                            System.out.println("**************************************************");
                            System.out.printf("Received Packet: %s\nProtocol Name: HTTP\nLength: %-4d\nHeader Length: %d\nSource IP: %s\nDestination IP: %s\n", new Date(packet.getCaptureHeader().timestampInMillis()),packet.getCaptureHeader().wirelen(), hp.getHeaderLength(),sourceIP,destinationIP);
            
                        }
                        break;
                        
                    case 4:
                        System.exit(0);
                }
                
            }  
        };
    
    //We will create a loop and ask it to capture infinite packets
   pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, ""); 
    
   //Now close the pcap handle
   pcap.close();
     
}

//Method for converting Mac address to string    
private static String mac_string(byte[] mac){
    
    //StringBuilder creates an empty string builder with a acapacity of 16 elements
    StringBuilder buf = new StringBuilder();
    
    /*
    MAC addresses are 12 digit hexadecimal numbers
    Format: MM:MM:MM:SS:SS:SS
    Leftmost 6 digits called as Prefix is associated with adaptor manufacturer
    Rightmost digits represent identification number for the specific device
    */
    for(byte b : mac){
        if(buf.length() != 0){
            buf.append(':');
        }
        if(b >= 0 && b<16){
            buf.append('0');
        }
        buf.append(Integer.toHexString((b < 0)? b+256 : b).toUpperCase());
    }
    return buf.toString();
    
    }
}
