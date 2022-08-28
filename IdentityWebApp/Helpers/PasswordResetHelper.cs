using System.Net.Mail;
using System.Net;

namespace IdentityWebApp.Helpers
{
    public static class PasswordResetHelper
    {
        public static void PasswordResetSendEmail(string link, string email)
        {
            MailMessage mail = new MailMessage();
            SmtpClient smtpClient = new SmtpClient("smtp.sendgrid.net");

            mail.From = new MailAddress("metincelebi5534@hotmail.com");
            mail.To.Add(email);

            mail.Subject = $"www.identityuyeliksistemi.com::Şifre sıfırlama";
            mail.Body = "<h4>Şifrenizi yenilemek için lütfen aşağıdaki linke tıklayınız.</h4><hr/>";
            mail.Body += $"<a href='{link}'>şifre yenileme linki</a>";
            mail.IsBodyHtml = true;
            smtpClient.Port = 587;
            smtpClient.Credentials = new NetworkCredential("apikey", "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");
            smtpClient.Send(mail);
        }
    }
}