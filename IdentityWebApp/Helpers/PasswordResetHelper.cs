using System.Net.Mail;
using System.Net;

namespace IdentityWebApp.Helpers
{
    public static class PasswordResetHelper
    {
        public static void PasswordResetSendEmail(string link)
        {
            MailMessage mail = new MailMessage();
            SmtpClient smtpClient = new SmtpClient("smtp.mandrillapp.com");

            mail.From = new MailAddress("metincelebi5534@hotmail.com");
            mail.To.Add("mcelebi@protel.com.tr");

            mail.Subject = $"www.blabla.com::Şifre sıfırlama";
            mail.Body = "<h2>Şifrenizi yenilemek için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            mail.Body += $"<a href='{link}'>şifre yenileme linki</a>";
            mail.IsBodyHtml = true;
            smtpClient.Port = 587;
            smtpClient.Credentials = new NetworkCredential("", "");
            smtpClient.Send(mail);
        }
    }
}