using System.ComponentModel.DataAnnotations;

namespace IdentityWebApp.ViewModels
{
    public class PasswordChangeViewModel
    {
        [Required(ErrorMessage = "Eski şifreniz gereklidir.")]
        [Display(Name = "Eski şifreniz")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakter olmak zorundadır.")]
        public string PasswordOld { get; set; }

        [Required(ErrorMessage = "Yeni şifreniz gereklidir.")]
        [Display(Name = "Yeni şifreniz")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakter olmak zorundadır.")]
        public string PasswordNew { get; set; }

        [Required(ErrorMessage = "Şifreniz tekrar gereklidir.")]
        [Display(Name = "Yeni şifrenizi tekrar giriniz")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakter olmak zorundadır.")]
        [Compare("PasswordNew", ErrorMessage = "Yeni şifreniz ile aynı değildir.")]
        public string PasswordConfirm { get; set; }
    }
}