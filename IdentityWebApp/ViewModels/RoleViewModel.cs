using System.ComponentModel.DataAnnotations;

namespace IdentityWebApp.ViewModels
{
    public class RoleViewModel
    {
        [Required(ErrorMessage = "Role ismi gereklidir.")]
        [Display(Name = "Role İsmi")]
        public string Name { get; set; }

        public string Id { get; set; }
    }
}