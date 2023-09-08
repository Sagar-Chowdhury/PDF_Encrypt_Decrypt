import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.FileOutputStream;
import java.io.IOException;

public class PdfEncryptionExample {

    public static void main(String[] args) throws IOException {
        String inputFilePath = "D:\\NICED.pdf";
        String outputFilePath = "D:\\NICEDEncry.pdf";
        String password = "123456";

        try {
            PdfReader reader = new PdfReader(inputFilePath);
            PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(outputFilePath));
            stamper.setEncryption(password.getBytes(), password.getBytes(), PdfWriter.ALLOW_PRINTING, PdfWriter.ENCRYPTION_AES_128);
            stamper.close();
            System.out.println("PDF encrypted successfully!");
        } catch (IOException | DocumentException e) {
            e.printStackTrace();
        }
    }
}
