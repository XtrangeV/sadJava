import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JFrame;

public class Count_window
{

    /**
     * //@param args
     */
    //public static void main(String[] args)
    public Count_window()
    {
        JFrame frame=new JFrame("https count");
        https_count rtcp=new https_count("Https count","Https","count");
        frame.getContentPane().add(rtcp,new BorderLayout().CENTER);
        frame.pack();
        frame.setVisible(true);
        (new Thread(rtcp)).start();
        frame.addWindowListener(new WindowAdapter()
        {
            public void windowClosing(WindowEvent windowevent)
            {
                System.exit(0);
            }

        });
    }
} 