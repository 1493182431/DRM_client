import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

/**
 * @description: 数字水印类
 * @author：Favor
 * @date: 2024/5/31
 */
public class WaterMarkUtil {

    private static final int MARKER_LENGTH = 10;

    /**
     * 提取水印
     * @param inputFile
     * @return
     * @throws IOException
     */
    public static String extractWaterMark(File inputFile) throws IOException {
        byte[] fileData = FileUtils.readFileToByteArray(inputFile);

        StringBuilder markerLengthStr = new StringBuilder();
        int markerIndex = fileData.length / 2;
        for (int i = 0; i < MARKER_LENGTH; i++) {
            markerLengthStr.append((char) fileData[markerIndex + i]);
        }
        int markerLength = Integer.parseInt(markerLengthStr.toString());

        StringBuilder hiddenData = new StringBuilder();
        int dataIndex = markerIndex + MARKER_LENGTH;
        for (int i = 0; i < markerLength; i++) {
            int currentByte = 0;
            for (int j = 0; j < 8; j++) {
                currentByte = (currentByte << 1) | (fileData[dataIndex] & 1);
                dataIndex++;
            }
            hiddenData.append((char) currentByte);
        }

        return hiddenData.toString();
    }
}
