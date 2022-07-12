using System.ComponentModel.DataAnnotations;

namespace IdentityWebApp.ViewModels
{
    public class PasswordResetViewModel
    {
        [Required(ErrorMessage = "Email alanı gereklidir.")]
        [Display(Name = "Email adresiniz.")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "Yeni Şifreniz")]
        [Display(Name = "Şifreniz")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakterli olmalıdır.")]
        public string NewPassword { get; set; }
    }
}