using System;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security;
using iTextSharp.text.pdf;
using System.IO;
using Org.BouncyCastle.X509;
using System.Security.Cryptography.Pkcs;
using CryptoPro.Sharpei;
using iTextSharp.text.pdf.security;

namespace e_sign.Models
{

    /// <summary>
    /// По мотивам http://www.cryptopro.ru/forum2/Default.aspx?g=posts&t=2846
    /// Для сборки примера необходимо установить последнюю версию iTextSharp и определить переменную PDF_SIGNATURE_ENABLED
    /// </summary>
    public class ESignManager
    {
        [STAThread]
        public static int GetSign()
        {
            string[] certificates = new string[1] { "28DCE90EAEFBD25C" };

            string document = "request.pdf";
            string certificate_dn = certificates[0];

            // Находим секретный ключ по сертификату в хранилище MY
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly);
            X509Certificate2Collection found = store.Certificates.Find(
                X509FindType.FindBySerialNumber, certificate_dn, false);
            if (found.Count == 0)
            {
                Console.WriteLine("Секретный ключ не найден.");
                return 1;
            }
            if (found.Count > 1)
            {
                Console.WriteLine("Найдено более одного секретного ключа.");
                return 1;
            }
            X509Certificate2 certificate = found[0];

            /*
             * if (certificates.Length > 2)
            {
                //set password.
                Gost3410CryptoServiceProvider cert_key = certificate.PrivateKey as Gost3410CryptoServiceProvider;
                if (null != cert_key)
                {
                    var cspParameters = new CspParameters();
                    //копируем параметры csp из исходного контекста сертификата
                    cspParameters.KeyContainerName = cert_key.CspKeyContainerInfo.KeyContainerName;
                    cspParameters.ProviderType = cert_key.CspKeyContainerInfo.ProviderType;
                    cspParameters.ProviderName = cert_key.CspKeyContainerInfo.ProviderName;
                    cspParameters.Flags = cert_key.CspKeyContainerInfo.MachineKeyStore
                                      ? (CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore)
                                      : (CspProviderFlags.UseExistingKey);
                    cspParameters.KeyPassword = new SecureString();
                    foreach (var c in args[2])
                    {
                        cspParameters.KeyPassword.AppendChar(c);
                    }
                    //создаем новый контекст сертификат, поскольку исходный открыт readonly
                    certificate = new X509Certificate2(certificate.RawData);
                    //задаем криптопровайдер с установленным паролем
                    certificate.PrivateKey = new Gost3410CryptoServiceProvider(cspParameters);
                }
            }
            */

            PdfReader reader = new PdfReader(document);
            PdfStamper st = PdfStamper.CreateSignature(reader, new FileStream(document + "_signed.pdf", FileMode.Create, FileAccess.Write), '\0');
            PdfSignatureAppearance sap = st.SignatureAppearance;

            // Загружаем сертификат в объект iTextSharp
            X509CertificateParser parser = new X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] {
                parser.ReadCertificate(certificate.RawData)
            };

            sap.Certificate = parser.ReadCertificate(certificate.RawData);
            sap.Reason = "I like to sign";
            sap.Location = "Universe";
            sap.Acro6Layers = true;

            //sap.Render = PdfSignatureAppearance.SignatureRender.NameAndDescription;
            sap.SignDate = DateTime.Now;

            // Выбираем подходящий тип фильтра
            PdfName filterName = new PdfName("CryptoPro PDF");

            // Создаем подпись
            PdfSignature dic = new PdfSignature(filterName, PdfName.ADBE_PKCS7_DETACHED);
            dic.Date = new PdfDate(sap.SignDate);
            dic.Name = "PdfPKCS7 signature";
            if (sap.Reason != null)
                dic.Reason = sap.Reason;
            if (sap.Location != null)
                dic.Location = sap.Location;
            sap.CryptoDictionary = dic;

            int intCSize = 4000;
            Dictionary<PdfName, int> hashtable = new Dictionary<PdfName, int>();
            hashtable[PdfName.CONTENTS] = intCSize * 2 + 2;
            sap.PreClose(hashtable);
            Stream s = sap.GetRangeStream();
            MemoryStream ss = new MemoryStream();
            int read = 0;
            byte[] buff = new byte[8192];
            while ((read = s.Read(buff, 0, 8192)) > 0)
            {
                ss.Write(buff, 0, read);
            }

            // Вычисляем подпись
            ContentInfo contentInfo = new ContentInfo(ss.ToArray());
            SignedCms signedCms = new SignedCms(contentInfo, true);
            CmsSigner cmsSigner = new CmsSigner(certificate);
            signedCms.ComputeSignature(cmsSigner, false);
            byte[] pk = signedCms.Encode();

            // Помещаем подпись в документ
            byte[] outc = new byte[intCSize];
            PdfDictionary dic2 = new PdfDictionary();
            Array.Copy(pk, 0, outc, 0, pk.Length);
            dic2.Put(PdfName.CONTENTS, new PdfString(outc).SetHexWriting(true));
            sap.Close(dic2);

            Console.WriteLine("Документ {0} успешно подписан на ключе {1} => {2}.",
                document, certificate.Subject, document + "_signed.pdf");
            return 0;
        }
    }
}