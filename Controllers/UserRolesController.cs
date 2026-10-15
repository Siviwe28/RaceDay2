using Azure.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Client;
using RaceDay.Models.ViewModels;

namespace RaceDay.Controllers
{



    [Authorize(Roles = "Admin")]
    public class UserRolesController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserRolesController(
         UserManager<IdentityUser> userManager,

         RoleManager<IdentityRole> roleManager)

        {
            _userManager = userManager;
            _roleManager = roleManager;
        }


        public async Task<IActionResult> Index()
        {
            var users = await _userManager.Users.ToListAsync();
            var userRolesViewModelList = new List<Models.ViewModels.UserRolesViewModel>();
            foreach (var user in users)

            {
                var thisViewModel = new UserRolesViewModel
                {
                    UserId = user.Id,
                    Email = user.Email ?? "",
                    UserName = user.UserName ?? "",
                    Roles = await _userManager.GetRolesAsync(user)

                };
                userRolesViewModelList.Add(thisViewModel);
            }

            return View(userRolesViewModelList);
        }
        //GET:/UserRoles/Manager?userId=xx
        public async Task<IActionResult> Manage(string userId)
        {

            ViewBag.userId = userId;

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                ViewBag.ErrorMessage = $"User with Id = {userId} cannot be found!!";
                return View("NotFound");
            }

            ViewBag.UserName = user.UserName;
            var model = new List<ManageUserRolesViewModel>();

            foreach (var role in _roleManager.Roles.ToList())
            {
                var userRolesViewModel = new ManageUserRolesViewModel
                {
                    RoleId = role.Id,
                    RoleName = role.Name ?? ""
                };
                if (await _userManager.IsInRoleAsync(user, role.Name ?? ""))
                {
                    userRolesViewModel.IsSelected = true;

                }
                else
                {
                    userRolesViewModel.IsSelected = false;
                }
               model.Add(userRolesViewModel);
            }
            return View(model);
        }
        //POST:/UserRoles/Manage?userId
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Manage(List<ManageUserRolesViewModel> model, string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return View("NotFound");
            }
            var roles = await _userManager.GetRolesAsync(user);
            var result = await _userManager.RemoveFromRolesAsync(user, roles);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Cannot remove user existing roles");
                return View(model);
            }
            result = await _userManager.AddToRolesAsync(user, model.Where(x => x.IsSelected).Select(y => y.RoleName));
            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Cannot add selected roles to user");
                return View(model);
            }
            return RedirectToAction("Index");
        }
    }
}