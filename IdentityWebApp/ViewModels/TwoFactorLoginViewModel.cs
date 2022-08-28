using IdentityWebApp.Enums;
using System.ComponentModel.DataAnnotations;

namespace IdentityWebApp.ViewModels
{
    public class TwoFactorLoginViewModel
    {
        [Display(Name = "Doğrulama Kodunuz")]
        [Required(ErrorMessage = "Doğrulama kodu boş olamaz")]
        [StringLength(6, ErrorMessage ="Doğrulama kodunuz en fazla 6 haneli olabilir.")]
        public string VerificationCode { get; set; }

        public bool IsRememberMe { get; set; }
        public bool IsRecoverCode { get; set; }
        public TwoFactor TwoFactorType { get; set; }
    }
}