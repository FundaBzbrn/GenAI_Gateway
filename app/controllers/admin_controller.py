"""
GenAI Security Gateway - Admin Kontrolcüsü (Admin Controller)

Bu dosya, yönetici (admin) paneli üzerinden yapılan güvenlik konfigürasyonu değişikliklerini,
kullanıcı yönetimini ve kural güncellemelerini işler.
Güvenlik katmanlarını (Layer 1, 2, 3) anlık olarak açıp kapatma veya yapay zeka
hassasiyet eşiğini (threshold) değiştirme işlemleri buradan yönetilir.
Ayrıca sisteme yeni departmanlar ve şirketler ekleme yetkilerine de sahiptir.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, List
from pydantic import BaseModel
from app.services.database_manager import DatabaseManager
from app.controllers.auth_controller import verify_token, get_password_hash

router = APIRouter()

# DTOs
class CompanyCreate(BaseModel):
    name: str
    domain: Optional[str] = None

class EmployeeCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    phone: Optional[str] = None
    full_name: str = ""
    department: Optional[str] = None

# --- SUPER ADMIN ENDPOINTS ---

def verify_super_admin(payload: dict = Depends(verify_token)):
    if payload.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Super Admin privileges required")
    return payload

@router.get("/super/stats", tags=["Super Admin"])
async def get_super_stats(payload: dict = Depends(verify_super_admin)):
    """Süper admin tüm şirketlerin ve sistemin genel istatistiklerini görür."""
    stats = await DatabaseManager.get_stats()
    return stats

@router.get("/super/companies", tags=["Super Admin"])
async def get_all_companies(payload: dict = Depends(verify_super_admin)):
    """Süper admin tüm şirketleri listeler."""
    companies = await DatabaseManager.get_all_companies()
    return {"companies": companies}

@router.post("/super/companies", tags=["Super Admin"])
async def create_company(company: CompanyCreate, payload: dict = Depends(verify_super_admin)):
    """Süper admin yeni bir şirket oluşturur."""
    company_id = await DatabaseManager.create_company(company.name, company.domain)
    if not company_id:
        raise HTTPException(status_code=500, detail="Error creating company")
    return {"message": "Company created successfully", "company_id": company_id}

@router.post("/super/company-admin", tags=["Super Admin"])
async def create_company_admin(admin_data: EmployeeCreate, company_id: int, payload: dict = Depends(verify_super_admin)):
    """Süper admin bir şirkete yönetici (company_admin) atar."""
    existing_user = await DatabaseManager.get_user_by_username(admin_data.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    hashed_password = get_password_hash(admin_data.password)
    success = await DatabaseManager.create_user(
        username=admin_data.username, 
        password_hash=hashed_password,
        email=admin_data.email,
        phone=admin_data.phone,
        full_name=admin_data.full_name,
        role="company_admin",
        company_id=company_id
    )
    if not success:
        raise HTTPException(status_code=500, detail="Error creating company admin")
    return {"message": "Company admin created successfully"}

@router.get("/super/logs", tags=["Super Admin"])
async def get_all_logs(limit: int = 50, payload: dict = Depends(verify_super_admin)):
    """Süper admin tüm logları (sızıntıları) görür."""
    logs = await DatabaseManager.get_logs(limit=limit)
    return {"count": len(logs), "logs": logs}

@router.get("/super/company-details/{company_id}", tags=["Super Admin"])
async def get_company_details(company_id: int, payload: dict = Depends(verify_super_admin)):
    """Süper admin bir şirketin kullanıcılarını ve istatistiklerini görür."""
    users = await DatabaseManager.get_users_by_company(company_id)
    stats = await DatabaseManager.get_stats(company_id)
    return {
        "users": users,
        "stats": stats
    }

# --- COMPANY ADMIN ENDPOINTS ---

def verify_company_admin(payload: dict = Depends(verify_token)):
    role = payload.get("role")
    if role not in ["company_admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Company Admin privileges required")
    return payload

@router.get("/company/stats", tags=["Company Admin"])
async def get_company_stats(payload: dict = Depends(verify_company_admin)):
    """Şirket yöneticisi sadece kendi şirketinin istatistiklerini görür."""
    company_id = payload.get("company_id")
    if not company_id and payload.get("role") != "super_admin":
        raise HTTPException(status_code=400, detail="Company ID missing for user")
        
    stats = await DatabaseManager.get_stats(company_id=company_id)
    return stats

@router.post("/company/employees", tags=["Company Admin"])
async def create_employee(employee: EmployeeCreate, payload: dict = Depends(verify_company_admin)):
    """Şirket yöneticisi yeni bir çalışan (employee) ekler."""
    company_id = payload.get("company_id")
    if not company_id:
        raise HTTPException(status_code=400, detail="Company ID missing for admin")
        
    existing_user = await DatabaseManager.get_user_by_username(employee.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    hashed_password = get_password_hash(employee.password)
    success = await DatabaseManager.create_user(
        username=employee.username, 
        password_hash=hashed_password,
        email=employee.email,
        phone=employee.phone,
        full_name=employee.full_name,
        role="employee",
        company_id=company_id,
        department=employee.department
    )
    if not success:
        raise HTTPException(status_code=500, detail="Error creating employee")
    return {"message": "Employee created successfully"}

@router.get("/company/logs", tags=["Company Admin"])
async def get_company_logs(limit: int = 50, payload: dict = Depends(verify_company_admin)):
    """Şirket yöneticisi kendi çalışanlarının tüm loglarını (sızıntılarını) görür."""
    company_id = payload.get("company_id")
    if not company_id and payload.get("role") != "super_admin":
        raise HTTPException(status_code=400, detail="Company ID missing for admin")
        
    logs = await DatabaseManager.get_logs(limit=limit, company_id=company_id)
    return {"count": len(logs), "logs": logs}

@router.post("/company/logs/{log_id}/approve", tags=["Company Admin"])
async def approve_pending_log(log_id: str, payload: dict = Depends(verify_company_admin)):
    """Şirket yöneticisi bekleyen bir hassas veri gönderim talebini onaylar (ALLOW)."""
    success = await DatabaseManager.update_log_status(log_id, action="ALLOW", bypass_status="Approved")
    if not success:
        raise HTTPException(status_code=500, detail="Talep onaylanamadı.")
    return {"success": True, "message": "Talep başarıyla onaylandı."}

@router.post("/company/logs/{log_id}/reject", tags=["Company Admin"])
async def reject_pending_log(log_id: str, payload: dict = Depends(verify_company_admin)):
    """Şirket yöneticisi bekleyen bir hassas veri gönderim talebini reddeder (BLOCK)."""
    success = await DatabaseManager.update_log_status(log_id, action="BLOCK", bypass_status="Rejected")
    if not success:
        raise HTTPException(status_code=500, detail="Talep reddedilemedi.")
    return {"success": True, "message": "Talep başarıyla reddedildi."}

@router.get("/company/employees", tags=["Company Admin"])
async def get_company_employees(payload: dict = Depends(verify_company_admin)):
    """Şirket yöneticisi kendi şirketinin çalışanlarını listeler."""
    company_id = payload.get("company_id")
    if not company_id and payload.get("role") != "super_admin":
        raise HTTPException(status_code=400, detail="Company ID missing for admin")
        
    users = await DatabaseManager.get_users_by_company(company_id)
    return {"users": users}

@router.get("/company/top-leakers", tags=["Company Admin"])
async def get_company_top_leakers(payload: dict = Depends(verify_company_admin)):
    """Şirket yöneticisi kendi şirketinde en çok sızıntı yapanları görür."""
    company_id = payload.get("company_id")
    if not company_id and payload.get("role") != "super_admin":
        raise HTTPException(status_code=400, detail="Company ID missing for admin")
        
    logs = await DatabaseManager.get_logs(limit=1000, company_id=company_id)
    
    leaker_counts = {}
    for log in logs:
        if log.get("action") == "BLOCK":
            user_id = log.get("user_id", "Bilinmeyen")
            leaker_counts[user_id] = leaker_counts.get(user_id, 0) + 1
            
    sorted_leakers = [{"user_id": k, "leak_count": v} for k, v in sorted(leaker_counts.items(), key=lambda item: item[1], reverse=True)]
    return {"top_leakers": sorted_leakers}
