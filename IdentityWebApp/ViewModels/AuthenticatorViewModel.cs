using IdentityWebApp.Enums;
using System.ComponentModel.DataAnnotations;

namespace IdentityWebApp.ViewModels
{
    public class AuthenticatorViewModel
    {
        public string SharedKey { get; set; }
        public string AuthenticatorUri { get; set; }
        [Display(Name = "Doğrulama Kodunuz")]
        [Required(ErrorMessage = "Doğrulama kodu zorunludur")]
        public string VerificationCode { get; set; }
        [Display(Name = "İki adımlı kimlik doğrulama seçiniz")]
        public TwoFactor TwoFactorType { get; set; }
    }
}