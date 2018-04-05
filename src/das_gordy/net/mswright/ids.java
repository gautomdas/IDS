package das_gordy.net.mswright;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;

/**
 * @author Gautom Das and Prayag Gordy
 *
 * Description:
 * This is the code that was used to go through all of the files.
 * */

public class ids {
    //For testing all of the code
    public static void main(String[] args) throws FileNotFoundException {
        String alerts = "TxtFiles\\FriAlerts.txt";
        String master = "TxtFiles\\master_identifications.list.txt";
        String traffic = "D:\\Documents\\IntrustionFiles (1)\\IntrustionFiles\\traffic\\trafficFri.txt";
        HashSet<String> init = readMaster(master);
        List<String> masterList = new ArrayList<>(init);

        List<String> alertsList = new ArrayList<>(readAlerts(alerts));

        System.out.println(alertsList);
        System.out.println(alertsList.size());
        System.out.println(masterList);
        System.out.println(masterList.size());

        System.out.println("False Positives");
        System.out.println(FP(alertsList,masterList));
        System.out.println("True Positives");
        System.out.println(TP(alertsList, masterList));


        System.out.println("False Negatives");
        System.out.println(FN(alertsList,masterList,traffic));
        System.out.println("True Negatives");
        System.out.println(TN(alertsList,masterList,traffic));
    }

    //Regular reading for Alerts
    public static List<String> readAlerts(String file) throws FileNotFoundException {
        File k = new File(file);
        Scanner readFile = new Scanner(k);

        List<String> list = new ArrayList<>();

        boolean flag = false;
        //Add everything to List
        while (readFile.hasNext()){
            if(flag){
                list.add(correctReadAlerts(readFile.next()));
                flag = false;
            }
            else{
                if(readFile.next().equals("IP")){
                    flag = true;
                }
            }
        }

        return list;
    }

    //Regular reading for the Master file
    public static HashSet<String> readMaster(String file) throws FileNotFoundException {
        File k = new File(file);
        Scanner readFile = new Scanner(k);

        HashSet<String> set = new HashSet<String>();

        boolean flag = false;
        //Add everything to hashset
        while (readFile.hasNext()){
            if(flag){

                String[] tot = readFile.nextLine().split(", ");
                if(tot.length > 1){
                    for(String ip:tot){
                        set.add(correct(ip.replaceAll("\\s+", "")));
                    }
                }
                else{
                    set.add(correct(tot[0].replaceAll("\\s+", "")));
                }
                flag = false;
            }
            else{
                if(readFile.next().equals("Attacker:")){
                    flag = true;
                }
            }
        }

        return set;
    }

    //Fixes formatting for Master
    public static String correct(String given){
        String[] split = given.split("\\.");
        String front_removed_zero = "";
        for(String part:split){
            String[] check = part.split("");
            String fina = "";
            if(check[0].equals("0") && check[1].equals("0")){
                fina = check[2];
            }
            else if(check[0].equals("0")){
                fina = check[1]+check[2];
            }
            else{
                fina = part;
            }
            front_removed_zero = front_removed_zero+"."+fina;
        }
        return front_removed_zero.substring(1, front_removed_zero.length());
    }

    //Fix formatting for everything else
    public static String correctReadAlerts(String given){
        String[] split = given.split("\\.");
        if(split.length>2) {
            String fina = "";
            for (int i = 0; i < split.length - 1; i++) {
                fina = fina + split[i] + ".";
            }
            return fina.substring(0, fina.length() - 1);
        }
        return given;
    }

    //False Positive count
    public static int FP(List<String> alerts, List<String> master){
        int count = 0;
        for(String ip:alerts){
            if(!(master.contains(ip))){
                count += 1;
            }
        }
        return count;
    }

    //True Positive count
    public static int TP(List<String> alerts, List<String> master){
        int count = 0;
        for(String ip:master){
            for(String second_ip: alerts){
                if(second_ip.equals(ip)){
                    count += 1;
                }
            }
        }
        return count;
    }

    //False Negative count
    public static int FN(List<String> alerts, List<String> master, String file) throws FileNotFoundException {
        File k = new File(file);
        Scanner readFile = new Scanner(k);
        int count = 0;
        boolean flag = false;

        //Active checking to go super saiyan through the code
        while (readFile.hasNext()){
            if(flag){
                String out = correctReadAlerts(readFile.next());

                if(master.contains(out)&&(!(alerts.contains(out)))){
                    count += 1;
                }

                flag = false;
            }
            else{
                if(readFile.next().equals("IP")){
                    flag = true;
                }
            }
        }
        return count;
    }

    //True Negative count
    public static int TN(List<String> alerts, List<String> master, String file) throws FileNotFoundException {
        File k = new File(file);
        Scanner readFile = new Scanner(k);
        int count = 0;
        boolean flag = false;

        //Active checking for the fastest possible time
        while (readFile.hasNext()){
            if(flag){
                String out = correctReadAlerts(readFile.next());

                if(!master.contains(out)&&(!(alerts.contains(out)))){
                    count += 1;
                }

                flag = false;
            }
            else{
                if(readFile.next().equals("IP")){
                    flag = true;
                }
            }
        }
        return count;
    }
}//end of IDS test
