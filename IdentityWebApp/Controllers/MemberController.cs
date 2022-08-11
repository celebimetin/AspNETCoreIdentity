using IdentityWebApp.Enums;
using IdentityWebApp.Models;
using IdentityWebApp.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityWebApp.Controllers
{
    [Authorize]
    public class MemberController : BaseController
    {
        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager) : base(userManager, signInManager, null) { }

        public IActionResult Index()
        {
            var user = _userManager.FindByNameAsync(User.Identity.Name).Result;
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            return View(userViewModel);
        }

        public IActionResult UserEdit()
        {
            var user = CurrentUser;
            var userViewModel = user.Adapt<UserViewModel>();
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));
            return View(userViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> UserEdit(UserViewModel userViewModel, IFormFile userPicture)
        {
            ModelState.Remove("Password");

            if (ModelState.IsValid)
            {
                var user = CurrentUser;

                if (userPicture != null && userPicture.Length > 0)
                {
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(userPicture.FileName);
                    var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/Picture", fileName);

                    using (var stream = new FileStream(path, FileMode.Create))
                    {
                        await userPicture.CopyToAsync(stream);
                        user.Picture = "/Picture/" + fileName;
                    }
                }
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.City = userViewModel.City;
                user.BirthDay = userViewModel.BirthDay;
                user.Gender = (int)userViewModel.Gender;

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    await _userManager.UpdateSecurityStampAsync(user);

                    await _signInManager.SignOutAsync();
                    await _signInManager.SignInAsync(user, true);

                    ViewBag.success = "true";
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(userViewModel);
        }

        public IActionResult PasswordChange()
        {
            return View();
        }

        [HttpPost]
        public IActionResult PasswordChange(PasswordChangeViewModel passwordChange)
        {
            if (ModelState.IsValid)
            {
                var user = CurrentUser;
                if (user != null)
                {
                    bool exist = _userManager.CheckPasswordAsync(user, passwordChange.PasswordOld).Result;
                    if (exist)
                    {
                        var result = _userManager.ChangePasswordAsync(user, passwordChange.PasswordOld, passwordChange.PasswordNew).Result;
                        if (result.Succeeded)
                        {
                            _userManager.UpdateSecurityStampAsync(user);

                            _signInManager.SignOutAsync();
                            _signInManager.PasswordSignInAsync(user, passwordChange.PasswordNew, true, false);

                            ViewBag.success = "true";
                        }
                        else
                        {
                            AddModelError(result);
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Eski şifreniz yanlıştır.");
                    }
                }
            }
            return View(passwordChange);
        }

        public void Logout()
        {
            _signInManager.SignOutAsync();
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        [Authorize(Roles = "editor,admin")]
        public IActionResult Editor()
        {
            return View();
        }

        [Authorize(Roles = "manager,admin")]
        public IActionResult Manager()
        {
            return View();
        }

        [Authorize(Policy = "AnkaraPolicy")]
        public IActionResult ClaimAuthorize()
        {
            return View();
        }

        public async Task<IActionResult> ExchangeRedirect()
        {
            var result = User.HasClaim(x => x.Type == "ExpireDateExchange");
            if (!result)
            {
                var ExpireDateExchange = new Claim("ExpireDateExchange", DateTime.Now.AddDays(30).Date.ToShortDateString(), ClaimValueTypes.String, "Internal");

                await _userManager.AddClaimAsync(CurrentUser, ExpireDateExchange);
                await _signInManager.SignOutAsync();
                await _signInManager.SignInAsync(CurrentUser, true);
            }
            return RedirectToAction("Exchange");
        }

        [Authorize(Policy = "ExchangePolicy")]
        public IActionResult Exchange()
        {
            return View();
        }
    }
}