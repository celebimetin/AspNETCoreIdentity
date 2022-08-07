using System.Net;
using System.Net.Mail;

namespace IdentityWebApp.Helpers
{
    public static class EmailConfirmation
    {
        public static void EmailConfirmationSend(string link, string email)
        {
            MailMessage mail = new MailMessage();
            SmtpClient smtpClient = new SmtpClient("smtp.mandrillapp.com");

            mail.From = new MailAddress("metincelebi5534@hotmail.com");
            mail.To.Add(email);

            mail.Subject = $"www.blabla.com::Email doğrulama";
            mail.Body = "<h2>Email adresinizi doğrulamak için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            mail.Body += $"<a href='{link}'>Email doğrulama linki</a>";
            mail.IsBodyHtml = true;
            smtpClient.Port = 587;
            smtpClient.Credentials = new NetworkCredential("", "");
            smtpClient.Send(mail);
        }
    }
}