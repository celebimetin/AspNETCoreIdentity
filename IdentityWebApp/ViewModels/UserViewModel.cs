using IdentityWebApp.Enums;
using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityWebApp.ViewModels
{
    public class UserViewModel
    {
        [Required(ErrorMessage = "Kullanıcı ismi gereklidir.")]
        [Display(Name = "Kullanıcı Adı")]
        public string UserName { get; set; }

        [Display(Name = "Telefon Numarası")]
        public string PhoneNumber { get; set; }

        [Required(ErrorMessage = "Email Adresi gereklidir.")]
        [Display(Name = "Email Adresi")]
        [EmailAddress(ErrorMessage = "Email adresi doğru formatta değildir.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Şifre gereklidir.")]
        [Display(Name = "Şifre")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Şehir")]
        public string City { get; set; }

        public string Picture { get; set; }

        [Display(Name = "Tarih")]
        [DataType(DataType.Date)]
        public DateTime? BirthDay { get; set; }

        [Display(Name = "Cinsiyet")]
        public Gender Gender { get; set; }
    }
}