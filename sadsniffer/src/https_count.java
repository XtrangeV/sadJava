//https_count .java
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYItemRenderer;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.Second;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

import java.awt.*;

public class https_count extends ChartPanel implements Runnable
{
    public static TimeSeries timeSeries;
    private long value=0;

    public https_count(String chartContent, String title, String yaxisName)
    {
        super(createChart(chartContent,title,yaxisName));
    }

    public static JFreeChart createChart(String chartContent,String title,String yaxisName){

        timeSeries = new TimeSeries(chartContent,Millisecond.class);

        TimeSeriesCollection timeseriescollection = new TimeSeriesCollection(timeSeries);
        JFreeChart jfreechart = ChartFactory.createTimeSeriesChart(title,"tims (s)",yaxisName,timeseriescollection,true,true,false);
        XYPlot xyplot = jfreechart.getXYPlot();

        xyplot.getRendererForDataset(xyplot.getDataset(0)).setSeriesPaint(0, Color.red);

        ValueAxis valueaxis = xyplot.getDomainAxis();
        valueaxis.setAutoRange(true);
        valueaxis.setFixedAutoRange(30000D);

        valueaxis = xyplot.getRangeAxis();


        valueaxis = xyplot.getRangeAxis();


        //valueaxis.setRange(0.0D,200D);  

        return jfreechart;
    }

    public void run()
    {
        while(true)
        {
            try
            {
                timeSeries.add(new Millisecond(), sniffer.https_count);
                //timeSeries2.add(new Millisecond(), randomNum());
                Thread.sleep(300);
            }
            catch (InterruptedException e)  {}
        }
    }
}
