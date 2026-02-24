//==============================================================================================================================================================
// UI Elements
//==============================================================================================================================================================
const layout = document.getElementById("layout");
//The container that holds all the group buttons
const groupButtonContainer = document.querySelector("#groupButtonContainer");
//The button that creates a group button
const buttonCreateGroup = document.querySelector("#buttonCreateGroup");
//The modal that pops up when the user wants to create a new group
const createGroupModal = document.getElementById("createGroupModal");
//The button that closes the createGroupModal
const createGroupModalCloseButton = document.getElementById("createGroupModalCloseBtn");
// The options modal overlay for the member buttons
const memberModalOverlay = document.getElementById("memberModalOverlay");
// The options modal for the member buttons
const memberModal = document.getElementById("memberModal");
//The button to toggle the member sidebar
const toggleRightSidebarbtn = document.getElementById("toggleSidebar");
//The member sidebar.
const rightSidebar = document.getElementById("rightSidebar");
//The options modal overlay for te group buttons
const groupModalOverlay = document.getElementById("groupModalOverlay");
//The options modal for the group buttons
const groupModal = document.getElementById("groupModal");
// The container that holds the member buttons
const memberContainer = document.querySelector("#memberContainer");
//The button to open invitations
const invitationButton = document.getElementById("invitations");
// The invitation modal
const invitationModal = document.getElementById("invitationModal");
//The button to close the invitation modal
const invatationModalCloseBtn = document.getElementById("invatationModalCloseBtn");
// The invite modal, not to be confused with the invitation modal
const inviteModal = document.getElementById("inviteMemberModal");
// The button to open the invite member modal, not to be confused with the invitation inbox
const inviteModalBtn = document.getElementById("inviteMemberBtn")
// The button to close the invite member modal, not to be confused with teh invitation inbox close btn
const inviteModalCloseBtn = document.getElementById("inviteModalCloseBtn")
// The invite member input
const inviteMemberInput = document.getElementById("inviteMemberInput");
// The container for all the invites
const invitationContainer = document.getElementById("invitationContainer")

currentGroup = null;

//==============================================================================================================================================================
// Functions
//==============================================================================================================================================================

//Selects the first applicable group
function SelectNewGroup() {
    if (groupButtonContainer.children.length > 0) {
        groupButtonContainer.children[0].classList.add("is-selected");
        groupButtonContainer.children[0].click();
    }
}

//Creates a new group button and adds it to the list.
function CreateButtonForGroup(groupName, groupId) {
    const button = document.createElement("button");
    button.textContent = groupName;

    button.className = "item";
    //This will display the new page for the dashboard
    button.addEventListener("click", () => {
        //TODO: Display the stuff in the dashboard page

        loadMembers(groupId);
        currentGroup = groupId;
    });

    //This brings up the group modal options
    button.addEventListener("contextmenu", (event) => {
        event.preventDefault(); // stops the browser menu
        DisplayModal(groupModalOverlay, groupModal, false, event);
    });

    //Add the button to the container
    document.getElementById("groupButtonContainer").appendChild(button);
    if (document.getElementById("groupButtonContainer").children.length === 1) {
        SelectNewGroup();
    }
}
function CreateButtonForMember(membername) {
    const button = document.createElement("button");
    button.textContent = membername;

    button.className = "item";

    //Add the button to the container
    document.getElementById("memberContainer").appendChild(button);
}
//TODO: maybe move this to a project wide js file?
/**
 * Displays modal
 * @param modalOverlay The overlay responsible for the modal
 * @param modal The actual modal, the content
 * @param bLeftHanded Should the modal be displayed on the left or right side of the cursor
 * @param e The click event that caused the modal to be displayed
*/
function DisplayModal(modalOverlay, modal, bLeftHanded, e) {
    modalOverlay.style.display = "block";

    const modalWidth = modal.offsetWidth;
    const padding = 10;


    let xPos = 0;

    if (bLeftHanded) {
        xPos = e.clientX - modalWidth - padding;
    } else {
        xPos = e.clientX + padding;
    }

    let top = e.clientY + padding;

    if (xPos < padding) xPos = padding;
    if (top + modal.offsetHeight > window.innerHeight) {
        top = window.innerHeight - modal.offsetHeight - padding;
    }

    modal.style.left = `${xPos}px`;
    modal.style.top = `${top}px`;

}

//TODO: maybe move this to a project wide js file?
function closeModalFn(modalOverlay) {
    modalOverlay.style.display = "none";
}

async function loadUserGroups() {
    try {
        const res = await fetch("/groups/user_group", {
            method: "GET",
            headers: { "Accept": "application/json" },
            // IMPORTANT if your frontend is on a different domain/port:
            // credentials: "include",
        });

        // Handle not-logged-in (401)
        if (res.status === 401) {
            const err = await res.json();
            console.log("Not logged in:", err.message);
            // e.g. redirect:
            // window.location.href = "/login";
            return;
        }

        if (!res.ok) {
            throw new Error(`Request failed: ${res.status}`);
        }

        const data = await res.json(); // { groups: ... }

        renderGroups(data.groups);

    } catch (e) {
        console.error("Error loading groups:", e);
    }
}

function renderGroups(groups) {
    for (const g of groups) {
        CreateButtonForGroup(g.name, g.group_id);
    }
    return;
}

async function createUserGroup(name) {
    const res = await fetch("/groups/create_user_group", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body: JSON.stringify({ name }),
        // If frontend is on a different origin/port, uncomment:
        // credentials: "include",
    });

    const data = await res.json().catch(() => ({})); // in case non-JSON error

    if (res.status === 401) {
        // Not logged in
        console.log(data.message || "Not logged in");
        // window.location.href = "/login";
        return;
    }

    if (res.status === 400) {
        // Validation error (e.g., missing name)
        alert(data.message || "Bad request");
        return;
    }

    if (!res.ok) {
        console.error("Server error:", res.status, data);
        alert("Something went wrong.");
        return;
    }

    // Success
    // data = { success: true, group_id: "...", user_key: "...", admin_key: "..." }
    return data;
}


async function loadMembers(group) {
    try {
        const route = `/groups/${group}/group_users`
        const res = await fetch(route, {
            method: "GET",
            headers: { "Accept": "application/json" },
            // IMPORTANT if your frontend is on a different domain/port:
            // credentials: "include",
        });

        // Handle not-logged-in (401)
        if (res.status === 401) {
            const err = await res.json();
            console.log("Not logged in:", err.message);
            // e.g. redirect:
            // window.location.href = "/login";
            return;
        }

        if (!res.ok) {
            throw new Error(`Request failed: ${res.status}`);
        }

        const data = await res.json(); // { groups: ... }

        renderMembers(data.users);

    } catch (e) {
        console.error("Error loading groups:", e);
    }
}

async function loadInvitations() {
    try {
        const route = `/groups/get_user_invites`
        const res = await fetch(route, {
            method: "GET",
            headers: { "Accept": "application/json" },
            // IMPORTANT if your frontend is on a different domain/port:
            // credentials: "include",
        });

        // Handle not-logged-in (401)
        if (res.status === 401) {
            const err = await res.json();
            console.log("Not logged in:", err.message);
            // e.g. redirect:
            // window.location.href = "/login";
            return;
        }

        if (!res.ok) {
            throw new Error(`Request failed: ${res.status}`);
        }

        const data = await res.json(); // { groups: ... }

        renderInvitations(data.groups);

    } catch (e) {
        console.error("Error loading invitations:", e);
    }
}

async function inviteMember(groupId, adminKey, membername) {
    const res = await fetch("/groups/invite_user", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body: JSON.stringify({
             group_id: groupId,
            invited_user_name: membername
        }),
        // If frontend is on a different origin/port, uncomment:
        // credentials: "include",
    });

    const data = await res.json().catch(() => ({})); // in case non-JSON error

    if (res.status === 401) {
        // Not logged in
        console.log(data.message || "Not logged in");
        // window.location.href = "/login";
        return data;
    }

    if (res.status === 400) {
        // Validation error (e.g., missing name)
        alert(data.message || "Bad request");
        return data;
    }

    if(res.status === 403){
        alert(data.message || "Invalid username")
        return data;
    }

    if (!res.ok) {
        console.error("Server error:", res.status, data);
        alert("Something went wrong.");
        return data;
    }

    // Success
    console.log("Invited member:", data);
    // data = { success: true, group_id: "...", user_key: "...", admin_key: "..." }
    return data;
}

async function joinGroup(groupId) {
    const res = await fetch("/groups/join_group", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body: JSON.stringify({
             group_id: groupId
        }),
        // If frontend is on a different origin/port, uncomment:
        // credentials: "include",
    });

    const data = await res.json().catch(() => ({})); // in case non-JSON error

    if (res.status === 401) {
        // Not logged in
        console.log(data.message || "Not logged in");
        // window.location.href = "/login";
        return;
    }

    if (res.status === 400) {
        // Validation error (e.g., missing name)
        alert(data.message || "Bad request");
        return;
    }

    if(res.status === 403){
        alert(data.message || "Invalid username")
        return;
    }

    if (!res.ok) {
        console.error("Server error:", res.status, data);
        alert("Something went wrong.");
        return;
    }
    // data = { success: true, ...
    return data;
}

async function denyInvite(groupId) {
    const res = await fetch("/groups/deny_invite", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body: JSON.stringify({
             group_id: groupId
        }),
        // If frontend is on a different origin/port, uncomment:
        // credentials: "include",
    });
}

function renderMembers(users) {
    memberContainer.replaceChildren();
    for (const u of users) {
        CreateButtonForMember(u.username);
    }
    return;
}

function renderInvitations(invites){
    invitationContainer.replaceChildren();
    console.log(invites.length)
    for (const inv of invites){
        CreateInvitationEntry(inv)
    }
}


//Creates a new group button and adds it to the list.
function CreateInvitationEntry(invitation) {
    const box = document.createElement("div");
    box.className = "box";

    const text = document.createElement("p");
    text.textContent = `Group: ${invitation.name}`;

    const button1 = document.createElement("button");
    button1.textContent = "Accept";

    const button2 = document.createElement("button");
    button2.textContent = "Deny";

    box.appendChild(text);
    box.appendChild(button1);
    box.appendChild(button2);
    invitationContainer.appendChild(box);
    
    button1.addEventListener("click", () => {
        //TODO:
        joinGroup(invitation._id).then(result => {
            console.log(result.success);
            box.remove();
        })
        .catch(err => {
            console.error(err.message);
        });
    });
    button2.addEventListener("click", () => {
        //TODO:
        denyInvite(invitation._id);
        box.remove();
    });
}


//==============================================================================================================================================================
// Setup
//==============================================================================================================================================================


invatationModalCloseBtn.addEventListener("click", (e) =>{
    invitationModal.classList.remove("show");
});

invitationButton.addEventListener("click", (e) =>{
    invitationModal.classList.add("show");
    loadInvitations();
});

inviteModalCloseBtn.addEventListener("click", (e) =>{
    inviteMemberInput.value = "";
    inviteModal.classList.remove("show");
});

inviteModalBtn.addEventListener("click", (e) =>{
    inviteModal.classList.add("show");
});

// Group selection logic
groupButtonContainer.addEventListener("click", (e) => {
    const clicked = e.target.closest("button");
    if (!clicked) return;

    groupButtonContainer.querySelectorAll(".item.is-selected").forEach((item) => {
        item.classList.remove("is-selected");
    });

    clicked.classList.add("is-selected");
});

//TODO invitation selection logic


//Setup close button for create group modal
createGroupModalCloseButton.addEventListener("click", () => {
    createGroupModal.classList.remove("show");
    document.getElementById("createGroupNameInput").value = "";
});

//Setup create group modal submit handler
document.getElementById("createGroupForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const groupName = document.getElementById("createGroupNameInput").value;

    createUserGroup(groupName)
        .then(result => {
            CreateButtonForGroup(groupName, result.group_id);
        })
        .catch(err => {
            console.error(err.message);
        });


    document.getElementById("createGroupNameInput").value = "";
    createGroupModal.classList.remove("show");

});

//Setup invite submit handler
document.getElementById("inviteMemberForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const memberName = inviteMemberInput.value;

    console.log(currentGroup)

    inviteMember(currentGroup, null, memberName)
        .then(result => {
            //CreateButtonForGroup(groupName);
            console.log(result.success);
        })
        .catch(err => {
            console.error(err.message);
        });


    inviteMemberInput.value = "";
    inviteModal.classList.remove("show");

});


//Setup the createGroupButton to show the create group modal
buttonCreateGroup.addEventListener("click", (e) => {
    createGroupModal.classList.add("show");
});

//Setup the collapsing member sidebar logic
toggleRightSidebarbtn.addEventListener("click", () => {
    const collapsed = layout.classList.toggle("is-collapsed");
    toggleRightSidebarbtn.setAttribute("aria-expanded", String(!collapsed));
});

// Setup the Close when clicking outside member modal logic
memberModalOverlay.addEventListener("click", (e) => {

    if (!memberModal.contains(e.target)) {
        closeModalFn(memberModalOverlay);
    }
});

// Setup the Close when clicking outside group modal logic
groupModalOverlay.addEventListener("click", (e) => {
    if (!groupModal.contains(e.target)) {
        closeModalFn(groupModalOverlay);
    }
});

//Setup the display modal when member button clicked logic
memberContainer.addEventListener("click", (e) => {
    const clicked = e.target.closest("button");
    if (!clicked) return;
    DisplayModal(memberModalOverlay, memberModal, true, e);
});

//Load the user groups when we first load the page
loadUserGroups();