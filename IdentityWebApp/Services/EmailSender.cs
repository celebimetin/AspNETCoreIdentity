using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Threading.Tasks;

namespace IdentityWebApp.Services
{
    public class EmailSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public EmailSender(IOptions<TwoFactorOptions> twoFactorOptions, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = twoFactorOptions.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string emailAdress)
        {
            string code = _twoFactorService.GetCodeVerificaiton().ToString();
            Execute(emailAdress, code).Wait();

            return code;
        }

        private async Task Execute(string email, string code)
        {
            var client = new SendGridClient(_twoFactorOptions.SendGrid_ApiKey);
            var from = new EmailAddress("metincelebi5534@hotmail.com");
            var subject = "İki Adımlı Kimlik Doğrulama Kodunuz.";
            var to = new EmailAddress(email);
            var htmlContent = $"<h4>Siteye giriş yapabilmeniz için doğrulama kodonuz aşağıdadır.</h4><h3>Kodunuz: {code}</h3>";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, null, htmlContent);
            var response = await client.SendEmailAsync(msg);
        }
    }
}