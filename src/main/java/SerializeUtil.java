import java.io.*;

/**
 * @description:
 * @author：Favor
 * @date: 2024/6/1
 */
public class SerializeUtil {
    public static final String TARGET_PATH = ".";// 项目内相对路径，用于存放程序输出的文件和序列号认证码文件

    /**
     * 将给定的对象序列化到指定的文件中
     *
     * @param object
     * @param filePath
     */
    public static <T> void serializeObjectToFile(T object, String filePath) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(object);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 从指定文件中读取对象，并将其反序列化为可用的 Java 对象
     *
     * @param filePath
     * @return
     */
    public static <T> T deserializeObjectFromFile(String filePath) {
        T object = null;

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            object = (T) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        return object;
    }
}
