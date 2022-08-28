using Microsoft.Extensions.Options;

namespace IdentityWebApp.Services
{
    public class SmsSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public SmsSender(IOptions<TwoFactorOptions> twoFactorOptions, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = twoFactorOptions.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string phone)
        {
            string code = _twoFactorService.GetCodeVerificaiton().ToString();

            //Sms Provider aracı olmadığı için kodlanmadı.
            //Execute(phone, code).Wait();

            return code = "123123";
        }
    }
}