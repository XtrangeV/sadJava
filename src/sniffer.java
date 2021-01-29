import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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

    //String mydev = "USB3.0 to Gigabit Ethernet Adapt";
    static String wireless_dev = "{84CA6333-9278-4150-81C2-94D3B097DFA6}";


    static String filter_s_ip = null;
    static String filter_d_ip = null;
    static String filter_pro = null;

    static int http_count = 0;
    public static int https_count = 0;
    static int count = 0;
    static String get_id;
    static String[] Detail = new String[30];
    static String[] sadtitle = {"Source","Dest","Ipv","Length","Protocol"};
    static Object[][] sadt = new Object[30][5];
    static JTable table = new JTable(sadt,sadtitle);
    static JTextArea jta = new JTextArea(30,30);
    static JButton bt1 = new JButton("源地址过滤");
    static JButton bt2 = new JButton("目的地址过滤");
    static JButton bt3 = new JButton("协议过滤");
    static JButton bt4 = new JButton("统计https");
    public static void init()
    {
        JFrame frame = new JFrame();

        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel panel = new JPanel();
        JPanel paneltop = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "sadshark", TitledBorder.CENTER,
                TitledBorder.TOP));

        paneltop.setLayout(new GridLayout(1,1));
        panel.setLayout(new GridLayout(2,1));

        paneltop.add(bt1);
        paneltop.add(bt2);
        paneltop.add(bt3);
        paneltop.add(bt4);

        panel.add(new JScrollPane(table));
        panel.add(new JScrollPane(jta));


        //frame.setLayout(new BoxLayout(frame,BoxLayout.Y_AXIS));
        //paneltop.setSize(100,10);
        frame.setLayout(new BorderLayout());

        frame.add(paneltop,BorderLayout.NORTH);
        frame.add(panel,BorderLayout.CENTER);
        frame.setTitle("sadShark");
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
            if(device.getName().contains(wireless_dev)) //wireless
            {
                isthis = i;
            }
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);

        }

        PcapIf device = alldevs.get(isthis);
        System.out
                .printf("\nChoosing '%s' :\n",
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

                    jta.setText(Detail[pos_line]);
                }
            }
        });
        //String rules

        bt1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                filter_s_ip = JOptionPane.showInputDialog("输入要过滤的源地址: ");
                for(int i =0;i<5;i++)
                {
                    for(int j =0;j<30;j++)
                    {
                        table.setValueAt(" ",j,i);
                    }
                }
                count=0;

            }
        });
        bt2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                filter_d_ip = JOptionPane.showInputDialog("输入要过滤的目的地址: ");
                for(int i =0;i<5;i++)
                {
                    for(int j =0;j<30;j++)
                    {
                        table.setValueAt(" ",j,i);
                    }
                }
                count=0;
            }
        });

        bt3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                filter_pro = JOptionPane.showInputDialog("输入要过滤的协议: ");
                for(int i =0;i<5;i++)
                {
                    for(int j =0;j<30;j++)
                    {
                        table.setValueAt(" ",j,i);
                    }
                }
                count=0;
            }
        });
        bt4.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new Count_window();
            }
        });
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>()
        {
            final Tcp tcp = new Tcp();
            final Http http = new Http();
            final Ip4 ip = new Ip4();

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
                    else if(tcp.source() == 25 || tcp.destination() == 25 || tcp.source() == 143 || tcp.destination() == 143)
                    {
                        protocol = "SMTP";
                    }
                    else if(tcp.source() == 443 || tcp.destination() == 443)
                    {
                        protocol = "Https";
                        https_count++;
                        System.out.println(https_count);
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
                if(packet.hasHeader(http))
                {
                    http_count++;
                    System.out.println(http_count);
                }
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
                        if(( sourceIP.equals(filter_s_ip) || sourceIP.equals("") ||filter_s_ip==null) && ( destinationIP.equals(filter_d_ip) || destinationIP.equals("") ||filter_d_ip==null ) && ( prot.equals(filter_pro) || prot.equals("") || filter_pro==null ) )
                        //System.out.println(( sourceIP.equals(filter_s_ip)) || filter_s_ip==null);
                        {
                            table.setValueAt(sourceIP, count, 0);
                            table.setValueAt(destinationIP, count, 1);
                            table.setValueAt(ip.version(), count, 2);
                            table.setValueAt(ip.length(), count, 3);
                            table.setValueAt(prot, count, 4);
                            allcount++;
                            Detail[count] = tcp.getPacket().toString();
                            System.out.println(Detail[count]);
                            count++;
                            count %= 30;
                        }

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