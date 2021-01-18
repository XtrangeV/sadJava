import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import javax.swing.*;
import javax.swing.border.TitledBorder;

public class sniffer
{
    String ans;
    static String get_id;
    static String[] Detail = new String[30];
    static String[] sadtitle = {"Source","Dest","Ipv","Length","Protocol"};
    static Object[][] sadt = new Object[30][5];
    static JTable table = new JTable(sadt,sadtitle);
    static JTextArea jta = new JTextArea(30,30);
    public static void init()
    {
        JFrame frame = new JFrame();

        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel panel = new JPanel();

        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "sadshark", TitledBorder.CENTER,
                TitledBorder.TOP));


        panel.setLayout(new GridLayout(2,1));
        panel.add(new JScrollPane(table));
        panel.add(new JScrollPane(jta));


        frame.add(panel);
        frame.pack();
        frame.setVisible(true);
    }

    public static void main(String[] args)
    //public sniffer()
    {

        init();

        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(alldevs, errbuf);

        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {

            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }

        System.out.println("Network devices found:");

        int i = 0;
        int isthis=0;
        for (PcapIf device : alldevs)
        {
            String description =
                    (device.getDescription() != null) ? device.getDescription()
                            : "No description available";
            if(description.equals("USB3.0 to Gigabit Ethernet Adapt"))
            {
                isthis = i;
            }
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);

        }

        PcapIf device = alldevs.get(isthis);
        System.out
                .printf("\nChoosing '%s' on your behalf:\n",
                        (device.getDescription() != null) ? device.getDescription()
                                : device.getName());

        int snaplen = 64 * 1024;

        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 1 * 1000;
        Pcap pcap =
                Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);



        if (pcap == null)
        {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
        table.addMouseListener(new MouseAdapter()
        {
            @Override
            public void mouseClicked(MouseEvent e)
            {
                super.mouseClicked(e);
                if(e.getButton() == MouseEvent.BUTTON1)
                {
                    Point mousepoint = e.getPoint();
                    int pos_line = table.rowAtPoint(mousepoint);

                    get_id = (String)table.getValueAt(pos_line,0);
                    //System.out.println(get_id);
                    //System.out.println(pos_line);
                    //System.out.println(Detail[pos_line]);
                    jta.setText(Detail[pos_line]);
                }
            }
        });
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>()
        {
            /*public void nextPacket(PcapPacket packet, String user)
            {
                final Tcp tcp = new Tcp();
                final Http http = new Http();
                final Ip4 ip = new Ip4();
                final Udp udp = new Udp();
                if(packet.hasHeader(tcp))
                {
                    System.out.println(tcp.source());
                }
                System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(),  // 实际捕获的长度
                        packet.getCaptureHeader().wirelen(), // 原来长度
                        user                                 // 用户信息


                );

            }*/
            final Tcp tcp = new Tcp();
            final Http http = new Http();
            final Ip4 ip = new Ip4();
            int count = 0;
             int allcount = 0;
            public String checkProtocol(PcapPacket pak)
            {
                Tcp tcp = new Tcp();
                Ip4 ip4 = new Ip4();
                String protocol = new String();
                if(pak.hasHeader(ip4) && pak.hasHeader(tcp))
                {
                    if(tcp.source() == 80 || tcp.destination() == 80)
                    {
                        protocol = "Http";
                    }
                    else if(tcp.source() == 21 || tcp.source() == 22 || tcp.destination() ==21 || tcp.destination() == 22)
                    {
                        protocol = "Ftp";
                    }
                    else if(tcp.source() == 25 || tcp.destination() == 25)
                    {
                        protocol = "SMTP";
                    }
                    else if(tcp.source() == 443 || tcp.destination() == 443)
                    {
                        protocol = "Https";
                    }
                    else
                    {
                        protocol = ((Integer)tcp.source()).toString();
                    }
                }
                return protocol;

            }
            public void nextPacket(PcapPacket packet, String user)
            {

                byte[] sIP = new byte[4];
                byte[] dIP = new byte[4];
                if(packet.hasHeader(tcp))
                {
                    packet.getHeader(tcp);
                    if(packet.hasHeader(ip))
                    {
                        sIP = ip.source();
                        dIP = ip.destination();

                        String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                        String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                        String prot = checkProtocol(packet);
                        //System.out.println("sou: "+sourceIP+" des: "+destinationIP+" IP version: "+ip.version()+" Length: "+ip.length()+" Protocol: "+prot);
                        //ans = "sou: "+sourceIP+" des: "+destinationIP+" IP version: "+ip.version()+" Length: "+ip.length()+" Protocol: "+prot;
                        table.setValueAt(sourceIP,count,0);
                        table.setValueAt(destinationIP,count,1);
                        table.setValueAt(ip.version(),count,2);
                        table.setValueAt(ip.length(),count,3);
                        table.setValueAt(prot,count,4);
                        allcount++;
                        Detail[count] = tcp.getPacket().toString();
                        //System.out.println(Detail[count]);
                        count++;
                        count %= 30;

                        //System.out.println(table.columnAtPoint(new Point()));
                    }
                }/*
                if (packet.hasHeader(http))
                {
                    packet.getHeader(http);
                    final String content_length =http.fieldValue(Http.Response.Content_Length);
                    final String response_code = http.fieldValue(Http.Response.ResponseCode);
                    //Find if the given packet is a Request/Response Pkt : First get the TCP header
                    packet.getHeader(tcp);
                    Integer int_tcp_source = new Integer(tcp.source());
                    Integer int_tcp_destination = new Integer(tcp.destination());
                    //if(int_tcp_source!=80 && content_length==null)
                    {
                        packet.getHeader(http);
                        final String ref = http.fieldValue(Http.Request.Referer);
                        final String req_url = http.fieldValue(Http.Request.RequestUrl);
                        String page_url = http.fieldValue(Http.Request.Host);
                        //System.out.printf("\n Referer  " +ref +req_url );//Get the URL
                        //System.out.printf("\nHost " +page_url);
                        //System.out.println(http.getPacket());
                        if(packet.hasHeader(ip))
                        {
                            sIP = ip.source();
                            dIP = ip.destination();

                            String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                            String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                            String prot = checkProtocol(packet);
                            System.out.println("sou: "+sourceIP+" des: "+destinationIP+" IP version: "+ip.version()+" Length: "+ip.length()+" Protocol: "+prot);

                        }


                    }
                }*/
            }
        };
        try
        {while(true)
            pcap.loop( 200,jpacketHandler, "sad");
        }catch(Exception e)
        {
            e.printStackTrace();
        }
        pcap.close();
    }


}