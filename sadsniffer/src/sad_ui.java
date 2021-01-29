import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.TitledBorder;
public class sad_ui
{
    static String ans;
    static Pcap pcap = null;
    static String[] sadtitle = {"Source","Dest","Ipv","Length","Protocol"};
    static Object[][] sadt = new Object[20][5];
    static JTable table = new JTable(sadt,sadtitle);
    public static void main(String[] args)
    {
        JFrame frame = new JFrame();
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "sadshark", TitledBorder.CENTER,
                TitledBorder.TOP));



        panel.add(new JScrollPane(table));

        frame.add(panel);
        frame.pack();
        frame.setVisible(true);
        //table.setValueAt(1,0,0);
        sniffer sad = new sniffer();

    }

}