import java.util.Scanner;

/**
 * @description: 客户端主程序
 * @author：Favor
 * @date: 2024/5/31
 */
public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        int count = 10;
        while (count>0) {
            System.out.println(new String(new char[50]).replace("\0", "\r\n"));
            System.out.println("您还能选择"+count+"次");
            System.out.println("========== 欢迎进入客户端系统 ==========");
            System.out.println("1. 生成授权Hash值");
            System.out.println("2. 解密文件");
            System.out.println("3. 提取数字水印");
            System.out.println("4. 退出系统");
            System.out.print("请选择操作（输入数字）：");
            String choice = scanner.nextLine();

            switch (Integer.parseInt(choice)) {
                case 1:
                    MainUtil.generateHash();
                    break;
                case 2:
                    MainUtil.decrypt();
                    break;
                case 3:
                    MainUtil.extractWaterMark();
                    break;
                case 4:
                    count = 0;
                    break;
                default:
                    System.out.println("\n无效选项，请重新选择");
                    break;
            }
            count--;
            System.out.println("按回车继续");
            scanner.nextLine();
        }
        System.out.println("\n感谢使用，再见！");
        scanner.close();
    }
}

