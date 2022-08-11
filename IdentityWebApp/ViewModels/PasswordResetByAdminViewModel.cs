using System.ComponentModel.DataAnnotations;

namespace IdentityWebApp.ViewModels
{
    public class PasswordResetByAdminViewModel
    {
        public string UserId { get; set; }
        [Required(ErrorMessage = "Zorunlu alan")]
        [Display(Name = "Yeni Şifre")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }
    }
}