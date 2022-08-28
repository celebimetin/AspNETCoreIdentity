using IdentityWebApp.Models;
using IdentityWebApp.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityWebApp.Controllers
{
    public class AdminController : BaseController
    {
        public AdminController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<AppRole> roleManager) : base(userManager, signInManager, roleManager) { }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Users()
        {
            return View(_userManager.Users.ToList());
        }

        public IActionResult Roles()
        {
            return View(_roleManager.Roles.ToList());
        }

        public IActionResult RoleCreate()
        {
            return View();
        }

        [HttpPost]
        public IActionResult RoleCreate(RoleViewModel roleViewModel)
        {
            var role = new AppRole();
            role.Name = roleViewModel.Name;
            var result = _roleManager.CreateAsync(role).Result;

            if (result.Succeeded)
            {
                return RedirectToAction("Roles");
            }
            else
            {
                AddModelError(result);
            }
            return View(roleViewModel);
        }

        public IActionResult RoleUpdate(string id)
        {
            var role = _roleManager.FindByIdAsync(id).Result;

            return View(role.Adapt<RoleViewModel>());
        }

        [HttpPost]
        public IActionResult RoleUpdate(RoleViewModel roleViewModel)
        {
            var role = _roleManager.FindByIdAsync(roleViewModel.Id).Result;
            if (role != null)
            {
                role.Name = roleViewModel.Name;
                var result = _roleManager.UpdateAsync(role).Result;

                if (result.Succeeded)
                {
                    return RedirectToAction("Roles");
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(roleViewModel);
        }

        public IActionResult RoleDelete(string id)
        {
            var role = _roleManager.FindByIdAsync(id).Result;
            if (role != null)
            {
                var result = _roleManager.DeleteAsync(role).Result;
            }
            return RedirectToAction("Roles");
        }

        public async Task<IActionResult> ResetUserPassword(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            PasswordResetByAdminViewModel passwordResetByAdminViewModel = new PasswordResetByAdminViewModel();
            passwordResetByAdminViewModel.UserId = user.Id;
            return View(passwordResetByAdminViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> ResetUserPassword(PasswordResetByAdminViewModel passwordResetByAdminViewModel)
        {
            var user = await _userManager.FindByIdAsync(passwordResetByAdminViewModel.UserId);
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _userManager.ResetPasswordAsync(user, token, passwordResetByAdminViewModel.NewPassword);

            await _userManager.UpdateSecurityStampAsync(user);
            return RedirectToAction("Users");
        }

        public IActionResult RoleAssign(string id)
        {
            TempData["userId"] = id;

            var user = _userManager.FindByIdAsync(id).Result;
            ViewBag.userName = user.UserName;

            var roles = _roleManager.Roles;
            var userRoles = _userManager.GetRolesAsync(user).Result;

            var roleAssignViewModels = new List<RoleAssignViewModel>();

            foreach (var item in roles)
            {
                RoleAssignViewModel roleAssign = new RoleAssignViewModel();
                roleAssign.RoleId = item.Id;
                roleAssign.RoleName = item.Name;

                if (userRoles.Contains(item.Name))
                {
                    roleAssign.Exist = true;
                }
                else
                {
                    roleAssign.Exist = false;
                }

                roleAssignViewModels.Add(roleAssign);
            }
            return View(roleAssignViewModels);
        }

        [HttpPost]
        public async Task<IActionResult> RoleAssign(List<RoleAssignViewModel> roleAssignViewModels)
        {
            var user = _userManager.FindByIdAsync(TempData["userId"].ToString()).Result;

            foreach (var item in roleAssignViewModels)
            {
                if (item.Exist)
                {
                    await _userManager.AddToRoleAsync(user, item.RoleName);
                }
                else
                {
                    await _userManager.RemoveFromRoleAsync(user, item.RoleName);
                }
            }
            return RedirectToAction("Users");
        }

        public void Logout()
        {
            _signInManager.SignOutAsync();
            RedirectToAction("Login", "Home");
        }

        public IActionResult Claims()
        {
            return View(User.Claims.ToList());
        }
    }
}