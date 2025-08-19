from app import app, db, Company, Layer, Page, User, DATA_DIR
from datetime import datetime, timedelta
import os
import glob
import shutil

def run_cleanup():
    with app.app_context():
        print(f"[{datetime.utcnow()}] Iniciando script de limpeza...")
        sixty_days_ago = datetime.utcnow() - timedelta(days=60)
        companies_to_delete = Company.query.filter(Company.expiry_date < sixty_days_ago).all()
        
        if not companies_to_delete:
            print("Nenhuma empresa para limpar.")
            return

        for company in companies_to_delete:
            print(f"-> Processando empresa expirada: {company.name} (ID: {company.id})")
            layers = Layer.query.filter_by(company_id=company.id).all()
            for layer in layers:
                print(f"  - Deletando arquivos da camada: {layer.filename}")
                base_path = os.path.join(DATA_DIR, os.path.splitext(layer.filename)[0])
                for filepath in glob.glob(f"{base_path}.*"):
                    try:
                        os.remove(filepath)
                    except OSError as e:
                        print(f"    - Erro ao remover {filepath}: {e}")
            
            print(f"-> Deletando registro da empresa e dados associados (usuários, páginas, camadas)...")
            # Deleta manualmente os dependentes antes de deletar a empresa
            User.query.filter_by(company_id=company.id).delete()
            Layer.query.filter_by(company_id=company.id).delete()
            Page.query.filter_by(company_id=company.id).delete()
            db.session.delete(company)
        
        db.session.commit()
        print(f"Limpeza completa. {len(companies_to_delete)} empresa(s) removida(s).")

if __name__ == '__main__':
    run_cleanup()